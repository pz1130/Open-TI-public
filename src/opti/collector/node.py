"""采集节点主循环：刷新规则、并发领取任务、常驻运行流式连接器、上报心跳。"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opti.collector import VERSION
from opti.collector.client import GatewayClient, GatewayError, mtls_context
from opti.collector.runner import JobRunner
from opti.collector.uploader import ItemUploader
from opti.core.config import ProjectRules
from opti.core.secrets import require_mask_key
from opti.gateway.jobs import JobKind
from opti.sdk import config_store
from opti.sdk.base import BaseConnector
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, readiness
from opti.sdk.runtime import ConnectorBlocked, RuntimePaths, collect, create

log = logging.getLogger("opti.collector")
Sleep = Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class CollectorSettings:
    gateway_url: str
    node_id: str
    token: str
    ca: Path | None = None
    cert: Path | None = None
    key: Path | None = None
    streams: tuple[str, ...] = ()
    concurrency: int = 4  # 富化任务的执行槽（境内在同步等待结果）
    run_concurrency: int = 2  # 采集运行的执行槽：运行可能持续数分钟，不能占用富化的槽
    lease_wait: float = 25.0
    rules_refresh: float = 60.0
    heartbeat_interval: float = 30.0
    config_dir: Path = field(default=Path("config/connectors"))
    state_dir: Path = field(default=Path("data"))

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> CollectorSettings:
        e = os.environ if env is None else env
        required = ("OPTI_GATEWAY_URL", "OPTI_NODE_ID", "OPTI_SECRET_COLLECTOR_NODE_TOKEN")
        missing = [k for k in required if not e.get(k)]
        if missing:
            raise ValueError(f"采集节点缺少环境变量：{', '.join(missing)}")
        if not e["OPTI_GATEWAY_URL"].startswith("https://"):
            raise ValueError("OPTI_GATEWAY_URL 必须使用 https（mTLS，设计文档 19）")

        def path(key: str) -> Path | None:
            value = e.get(key)
            return Path(value) if value else None

        streams = tuple(
            s.strip() for s in (e.get("OPTI_COLLECTOR_STREAMS") or "").split(",") if s.strip()
        )
        return cls(
            gateway_url=e["OPTI_GATEWAY_URL"],
            node_id=e["OPTI_NODE_ID"],
            token=e["OPTI_SECRET_COLLECTOR_NODE_TOKEN"],
            ca=path("OPTI_GATEWAY_CA"),
            cert=path("OPTI_NODE_CERT"),
            key=path("OPTI_NODE_KEY"),
            streams=streams,
            concurrency=int(e.get("OPTI_COLLECTOR_CONCURRENCY") or 4),
            run_concurrency=int(e.get("OPTI_COLLECTOR_RUN_CONCURRENCY") or 2),
            config_dir=path("OPTI_CONFIG_DIR") or Path("config/connectors"),
            state_dir=path("OPTI_STATE_DIR") or Path("data"),
        )

    def client(self) -> GatewayClient:
        if not (self.ca and self.cert and self.key):
            raise ValueError("需要 OPTI_GATEWAY_CA、OPTI_NODE_CERT、OPTI_NODE_KEY（mTLS）")
        return GatewayClient(
            self.gateway_url, self.token, verify=mtls_context(self.ca, self.cert, self.key)
        )


class CollectorNode:
    def __init__(
        self,
        settings: CollectorSettings,
        client: GatewayClient,
        *,
        registry: Registry | None = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._s = settings
        self._client = client
        self._registry = registry or Registry()
        self._sleep = sleep
        self._paths = RuntimePaths(config_dir=settings.config_dir, state_dir=settings.state_dir)
        self.uploader = ItemUploader(client, sleep=sleep)
        self._runner: JobRunner | None = None
        self._retired: list[JobRunner] = []
        self._rules: ProjectRules | None = None
        self._digest: str | None = None
        self._config_snapshot: (
            tuple[dict[str, dict[str, Any]], dict[str, dict[str, str | None]]] | None
        ) = None
        self._ready = asyncio.Event()
        self._streams: dict[str, asyncio.Task[None]] = {}
        self._stream_cursors = MemoryCursorStore()
        self._stream_status: dict[str, str] = {}
        self._running = 0
        self._remote_ids = frozenset(
            m.id for m in self._registry.manifests() if m.egress != "domestic"
        )

    def status(self) -> dict[str, Any]:
        return {
            "streams": dict(self._stream_status),
            "jobs_running": self._running,
            "buffered_items": self.uploader.buffered,
            "dropped_items": self.uploader.dropped,
            "rules_digest": self._digest,
            "connectors": readiness(
                self._registry, self._s.config_dir, EnvSecretProvider(), ids=self._remote_ids
            ),
        }

    async def run(self) -> None:
        require_mask_key()  # 与平台相同的 OPTI_SECRET_MASK_KEY；缺失时拒绝启动
        self.uploader.start()
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._rules_loop())
                tg.create_task(self._heartbeat_loop())
                for _ in range(max(1, self._s.concurrency)):
                    tg.create_task(self._job_loop(("enrich",)))
                for _ in range(max(1, self._s.run_concurrency)):
                    tg.create_task(self._job_loop(("run_connector",)))
        finally:
            await self._stop_streams()
            config_store.clear_current()
            await self.uploader.stop()
            for runner in [*self._retired, *([self._runner] if self._runner else [])]:
                await runner.aclose()

    async def _refresh_rules(self) -> None:
        digest, data = await self._client.rules()
        snapshot = await self._client.connector_config()
        if digest == self._digest and snapshot == self._config_snapshot:
            return
        config_store.set_current(*snapshot)
        rules = ProjectRules.model_validate(data)
        if self._runner is not None:
            self._retired.append(self._runner)  # 进行中的任务仍在用旧规则，停止时再关闭
        self._runner = JobRunner(
            registry=self._registry,
            rules=rules,
            paths=self._paths,
            uploader=self.uploader,
            saver=self._client.upload_evidence,
        )
        self._rules, self._digest = rules, digest
        self._config_snapshot = snapshot
        await self._restart_streams()
        log.info("已加载规则 %s", digest[:12])
        self._ready.set()

    async def _rules_loop(self) -> None:
        while True:
            try:
                await self._refresh_rules()
            except (GatewayError, ValueError) as e:
                log.warning("获取规则失败：%s", e)
            await self._sleep(self._s.rules_refresh if self._ready.is_set() else 5.0)

    async def _job_loop(self, kinds: tuple[JobKind, ...]) -> None:
        await self._ready.wait()
        while True:
            try:
                job = await self._client.lease(self._s.lease_wait, kinds)
            except GatewayError as e:
                log.warning("领取任务失败：%s", e)
                await self._sleep(5.0)
                continue
            if job is None:
                continue
            assert self._runner is not None
            self._running += 1
            try:
                result = await self._runner.run(job)
            finally:
                self._running -= 1
            await self._report(job.id, result)

    async def _report(self, job_id: str, result: dict[str, Any]) -> None:
        attempt = 0
        while True:
            try:
                await self._client.result(job_id, result)
                return
            except GatewayError as e:
                if not e.retriable:  # 409：任务已过期或不属于本节点
                    log.warning("任务 %s 的结果被网关拒绝：%s", job_id, e.status)
                    return
                await self._sleep(min(60.0, 2.0 ** min(attempt, 6)))
                attempt += 1

    async def _stop_streams(self) -> None:
        for task in self._streams.values():
            task.cancel()
        await asyncio.gather(*self._streams.values(), return_exceptions=True)
        self._streams = {}

    async def _restart_streams(self) -> None:
        await self._stop_streams()
        assert self._rules is not None
        self._streams = {
            cid: asyncio.create_task(self._stream(cid, self._rules)) for cid in self._s.streams
        }

    async def _stream(self, cid: str, rules: ProjectRules) -> None:
        attempt = 0
        while True:
            conn = None
            try:
                conn = create(
                    self._registry, cid, rules, paths=self._paths, cursors=self._stream_cursors
                )
                if not isinstance(conn, BaseConnector):
                    raise ConnectorBlocked(f"{cid} 不是连接器")
                self._stream_status[cid] = "running"
                async for item in collect(conn, build_query_plan(rules)):
                    await self.uploader.put(item)
                    attempt = 0
                self._stream_status[cid] = "ended"
            except ConnectorBlocked as e:  # 合规闸门拒绝：不重试
                self._stream_status[cid] = f"blocked: {e}"
                log.error("流式连接器 %s 未启动：%s", cid, e)
                return
            except Exception as e:  # 连接器内部已负责断线重连；到这里说明出了意外，退避后重启
                self._stream_status[cid] = f"error: {type(e).__name__}"
                log.warning("流式连接器 %s 异常退出：%s", cid, e)
            finally:
                if conn is not None:
                    with contextlib.suppress(Exception):
                        await conn.ctx.http().aclose()
            await self._sleep(min(300.0, 5.0 * 2**attempt))
            attempt += 1

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await self._client.heartbeat(VERSION, self.status())
            except GatewayError as e:
                log.warning("心跳失败：%s", e)
            await self._sleep(self._s.heartbeat_interval)
