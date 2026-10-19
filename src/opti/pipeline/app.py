"""应用装配：数据库、规则、富化器、处理器、告警分发器（worker、调度器与命令行共用）。"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from opti.alerting.config import AlertingConfig
from opti.alerting.dispatcher import AlertDispatcher, Route, Sink, build_routes
from opti.alerting.runtime import ConfigBoundTickets, DispatcherCache, ticket_source
from opti.configs.runtime import ConfigRuntime, ConfigSnapshot, process_name
from opti.core.config import ProjectRules
from opti.core.kev import SoftwareMatcher
from opti.core.leakposts import PUBLIC_LINK_HOSTS
from opti.core.secretbox import Keyring
from opti.core.vendors import PartyMatcher
from opti.db import repo
from opti.db.cursors import PgCursorStore
from opti.db.engine import make_engine, make_sessionmaker
from opti.gateway.dispatch import remote_enricher
from opti.gateway.jobs import JobQueue, ValkeyJobQueue
from opti.organization import Organization
from opti.pipeline.campaigns import CampaignConfig
from opti.pipeline.coderepos import CODE_ENRICHERS
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.evidence import EVIDENCE_ENRICHERS
from opti.pipeline.llm_runtime import RuntimeCache, warn_legacy
from opti.pipeline.processor import DEFAULT_ENRICHERS, Processor
from opti.pipeline.retention import RetentionConfig
from opti.pipeline.social_accounts import ADAPTERS as SOCIAL_ADAPTERS
from opti.pipeline.versions import Pipeline, PipelineBuildFailed, PipelineCache
from opti.pipeline.watchlist import WATCH_ENRICHERS
from opti.sdk.base import BaseConnector, Enricher
from opti.sdk.context import EnvSecretProvider
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.models import RawItem
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.runtime import ConnectorBlocked, RuntimePaths, collect, create
from opti.sdk.scan import KeywordScan, scan_plan
from opti.settings import Settings
from opti.sharing import SharingConfig
from opti.siem import Sender, SenderCache
from opti.storage.artifacts import store_saver
from opti.storage.objects import ObjectStore, object_store_from_settings
from opti.takedown.config import TakedownConfig
from opti.takedown.hosting import TAKEDOWN_ENRICHERS
from opti.tickets.client import TicketClient
from opti.tickets.config import TicketsConfig

log = logging.getLogger("opti.app")
Closer = Callable[[], Awaitable[None]]


@dataclass
class App:
    settings: Settings
    config: ConfigRuntime
    registry: Registry
    paths: RuntimePaths
    engine: AsyncEngine
    sessions: async_sessionmaker[AsyncSession]
    pipelines: PipelineCache
    dispatchers: DispatcherCache
    closers: list[Closer] = field(default_factory=list)
    jobs: JobQueue | None = None  # remote 模式下的网关任务队列
    store: ObjectStore | None = None

    @property
    def takedown(self) -> TakedownConfig:
        return self.config.snapshot.takedown

    ticket_source: ConfigBoundTickets | None = None
    _tickets_override: TicketClient | None = field(default=None, repr=False)
    keyring: Keyring | None = None
    llm: RuntimeCache = field(default_factory=lambda: RuntimeCache(None))
    siem_cache: SenderCache | None = None

    @property
    def retention(self) -> RetentionConfig:
        return self.config.snapshot.retention

    @property
    def campaigns(self) -> CampaignConfig:
        return self.config.snapshot.campaigns

    @property
    def tickets(self) -> TicketClient | None:
        if self._tickets_override is not None:
            return self._tickets_override
        return self.ticket_source.current() if self.ticket_source is not None else None

    @tickets.setter
    def tickets(self, client: TicketClient | None) -> None:
        self._tickets_override = client

    @property
    def tickets_cfg(self) -> TicketsConfig:
        return self.config.snapshot.tickets

    @property
    def sharing(self) -> SharingConfig:
        return self.config.snapshot.sharing

    @property
    def siem_senders(self) -> list[Sender]:
        return self.siem_cache.get(self.config.snapshot) if self.siem_cache is not None else []

    @property
    def rules(self) -> ProjectRules:
        return self.config.snapshot.rules

    @property
    def organization(self) -> Organization:
        return self.config.snapshot.organization

    @property
    def alerting(self) -> AlertingConfig:
        return self.config.snapshot.alerting

    @property
    def dispatcher(self) -> AlertDispatcher:
        return self.dispatchers.get(self.config.snapshot)

    @property
    def processor(self) -> Processor:
        return self.pipelines.get(self.config.snapshot).processor

    @property
    def enrichment(self) -> EnrichmentService:
        return self.pipelines.get(self.config.snapshot).enrichment

    async def close(self) -> None:
        await self.config.stop()
        await self.pipelines.close()
        for close in self.closers:
            await close()
        await self.engine.dispose()


def _create_enrichers(
    registry: Registry,
    rules: ProjectRules,
    paths: RuntimePaths,
    closers: list[Closer],
    *,
    jobs: JobQueue | None,
    remote_timeout: float,
) -> dict[str, Enricher]:
    out: dict[str, Enricher] = {}
    for eid in sorted(
        {
            *DEFAULT_ENRICHERS,
            *WATCH_ENRICHERS,
            *EVIDENCE_ENRICHERS,
            *TAKEDOWN_ENRICHERS,
            *CODE_ENRICHERS,
            "subdomains",
            *SOCIAL_ADAPTERS.values(),
        }
    ):
        if jobs is not None and registry.manifest(eid).egress == "overseas":
            # 境外富化器由采集节点执行（设计文档 3.4）；境内只检查是否启用与法务批准
            instance = load_instance_config(paths.config_dir, eid)
            if not (instance.enabled and instance.license_approved):
                log.warning("富化器 %s 未启用或未经批准，跳过", eid)
                continue
            cls = registry.load_class(eid)
            if issubclass(cls, Enricher):
                out[eid] = remote_enricher(cls, jobs, timeout=remote_timeout)
            continue
        try:
            e = create(registry, eid, rules, paths=paths)
        except ConnectorBlocked as ex:
            log.warning("富化器 %s 未启用：%s", eid, ex)
            continue
        if isinstance(e, Enricher):
            out[eid] = e
            closers.append(e.ctx.http().aclose)
    return out


async def build_app(
    settings: Settings,
    *,
    process: str | None = None,
    enrichers: Mapping[str, Enricher] | None = None,
    sinks: Sequence[Sink] | None = None,
    registry: Registry | None = None,
    jobs: JobQueue | None = None,
    store: ObjectStore | None = None,
) -> App:
    if not settings.database_url:
        raise RuntimeError("需要设置环境变量 OPTI_DATABASE_URL")
    engine = make_engine(settings.database_url)
    sessions = make_sessionmaker(engine)
    config = await ConfigRuntime.start(settings, sessions, process=process)
    keyring = config.keyring
    warn_legacy()
    llm = RuntimeCache(keyring)
    registry = registry or Registry()
    paths = RuntimePaths(config_dir=settings.config_dir, state_dir=settings.state_dir)
    closers: list[Closer] = []
    if settings.collector_mode == "remote" and jobs is None:
        if not settings.broker_url:
            raise RuntimeError("remote 模式需要 OPTI_BROKER_URL（Valkey，网关任务队列）")
        valkey = ValkeyJobQueue.from_url(settings.broker_url)
        closers.append(valkey.close)
        jobs = valkey
    if settings.collector_mode != "remote":
        jobs = None

    alert_http = RateLimitedHttpClient()
    closers.append(alert_http.aclose)

    def build_dispatcher(snap: ConfigSnapshot) -> AlertDispatcher:
        routes = (
            [Route.default(s) for s in sinks]
            if sinks is not None
            else build_routes(snap.alerting, alert_http, snap.alerting_secrets)
        )
        return AlertDispatcher(snap.alerting, routes, project_id=snap.rules.project)

    if store is None:
        s3 = object_store_from_settings(settings, EnvSecretProvider())
        if s3 is not None:
            try:
                await s3.ensure_bucket()
            except Exception as e:  # 存储暂时不可用不能阻止 worker 启动；取证会失败并重试
                log.warning("对象存储初始化失败：%s", type(e).__name__)
        store = s3
    if store is None:
        log.warning("未配置对象存储（OPTI_S3_ENDPOINT）：截图证据不会被保存")
    saver = store_saver(store) if store is not None else None
    leak_link_hosts = {
        source: tuple(
            load_instance_config(settings.config_dir, source).config.get("link_hosts") or hosts
        )
        for source, hosts in PUBLIC_LINK_HOSTS.items()
    }

    def build(snap: ConfigSnapshot) -> tuple[Pipeline, list[Closer]]:
        own: list[Closer] = []
        try:
            active = enrichers if enrichers is not None else _create_enrichers(
                registry, snap.rules, paths, own, jobs=jobs, remote_timeout=settings.remote_timeout
            )  # fmt: skip
            enrichment = EnrichmentService(
                active,
                timeout=snap.operations.scanning.enrichment_timeout_seconds,
                saver=saver,
                no_visit=lambda host: config.snapshot.takedown.platform_for(host) is not None,
            )
            processor = Processor(
                snap.rules, enrichment, software=SoftwareMatcher(snap.software),
                parties=PartyMatcher(snap.organization, snap.rules.domains.official, snap.vendors),
                leak_link_hosts=leak_link_hosts, llm=llm,
            )  # fmt: skip
            return Pipeline(enrichment, processor), own
        except Exception as exc:
            raise PipelineBuildFailed(own, exc) from exc

    siem_http = RateLimitedHttpClient()
    closers.append(siem_http.aclose)
    ticket_http = RateLimitedHttpClient()
    closers.append(ticket_http.aclose)
    return App(
        settings=settings,
        config=config,
        registry=registry,
        paths=paths,
        engine=engine,
        sessions=sessions,
        pipelines=PipelineCache(build, on_status=config.schedule_pipeline_status),
        dispatchers=DispatcherCache(build_dispatcher),
        closers=closers,
        jobs=jobs,
        store=store,
        ticket_source=ticket_source(lambda: config.snapshot, ticket_http),
        llm=llm,
        keyring=keyring,
        siem_cache=SenderCache(siem_http),
    )


_app: App | None = None


async def get_app() -> App:
    global _app
    if _app is None:
        _app = await build_app(Settings.from_env(), process=process_name("worker"))
        _app.config.start_background()
    if _app.keyring is None:
        ring = _app.config.keyring or Keyring.from_env(state_dir=_app.settings.state_dir)
        if ring is not None:
            _app.keyring = ring
            _app.config.set_keyring(ring)
            _app.llm.set_keyring(ring)
    return _app


def set_app(app: App | None) -> None:
    global _app
    _app = app


def current_app() -> App | None:
    return _app


async def run_connector_once(
    app: App,
    connector_id: str,
    *,
    enqueue: Callable[[RawItem], Awaitable[None]],
    max_items: int | None = None,
    seconds: float | None = None,
    allow_unapproved: bool = False,
    stop: asyncio.Event | None = None,
    scan: KeywordScan | None = None,
) -> int:
    """运行一次连接器：游标从数据库加载、结束时写回，每条结果交给 enqueue（通常是 ingest.kiq）。"""
    cursors = PgCursorStore()
    rules = app.rules
    conn = create(
        app.registry, connector_id, rules, paths=app.paths,
        allow_unapproved=allow_unapproved, cursors=cursors,
    )  # fmt: skip
    run_id: int | None = None
    items, status, message = 0, "ok", ""
    try:
        if not isinstance(conn, BaseConnector):
            raise ConnectorBlocked(f"{connector_id} 是富化器，不能作为采集任务运行")
        async with app.sessions() as s, s.begin():
            await cursors.load(s, connector_id)
            run_id = await repo.start_run(s, connector_id, datetime.now(UTC))
        try:
            plan = scan_plan(rules, scan) if scan is not None else build_query_plan(rules)
            # collect 标注为 AsyncIterator，实现是异步生成器，有 aclose。
            async with contextlib.aclosing(
                cast(
                    AsyncGenerator[RawItem, None],
                    collect(conn, plan, max_items=max_items, seconds=seconds),
                )
            ) as stream:
                async for item in stream:
                    await enqueue(item)
                    items += 1
                    if stop is not None and stop.is_set():
                        break  # 规则已更新：正常结束本次运行，由 run_stream 以新查询计划重连
        except Exception as e:  # 记录到 connector_run 后再抛出，便于健康监控（设计文档 5.4）
            status, message = "error", f"{type(e).__name__}: {e}"
            raise
    finally:
        # CancelledError 不属于 Exception。stop 已置位是规则更新后的正常结束，记成功；
        # 没有 stop 的中断仍记为失败。
        exc_type = sys.exc_info()[0]
        try:
            await conn.ctx.http().aclose()
        except Exception:
            log.warning("关闭连接器 %s 的 HTTP 客户端失败", connector_id, exc_info=True)
        if run_id is not None:
            stopped = stop is not None and stop.is_set()
            if exc_type is not None and status == "ok" and not stopped:
                status, message = "error", exc_type.__name__
            async with app.sessions() as s, s.begin():
                now = datetime.now(UTC)
                await cursors.flush(s, now)
                await repo.finish_run(
                    s, run_id, status=status, items=items, errors=int(status == "error"),
                    message=message, now=now,
                )  # fmt: skip
    return items


async def run_stream(
    app: App,
    connector_id: str,
    *,
    enqueue: Callable[[RawItem], Awaitable[None]],
    allow_unapproved: bool = False,
    stop_timeout: float = 30.0,
) -> int:
    """常驻流式连接器：规则 digest 变化时以新查询计划重新连接（与境外采集节点的做法一致）。"""
    while True:
        digest = app.config.snapshot.rules_digest
        stop = asyncio.Event()

        def on_change(
            _old: ConfigSnapshot,
            new: ConfigSnapshot,
            digest: str = digest,
            stop: asyncio.Event = stop,
        ) -> None:
            if new.rules_digest != digest:
                stop.set()

        unsubscribe = app.config.subscribe(on_change)
        run = asyncio.create_task(run_connector_once(
            app, connector_id, enqueue=enqueue, allow_unapproved=allow_unapproved, stop=stop
        ))  # fmt: skip
        waiter = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait({run, waiter}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            waiter.cancel()
            unsubscribe()
        if not stop.is_set():
            return run.result()
        if run in done:
            run.result()
        else:
            try:
                await asyncio.wait_for(asyncio.shield(run), stop_timeout)
            except TimeoutError:
                run.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await run
        log.info("规则已更新，%s 以新查询计划重新连接", connector_id)
