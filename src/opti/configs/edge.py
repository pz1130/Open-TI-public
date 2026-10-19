"""不能连数据库的边缘服务（intake、syslog）从 Valkey 或采集网关拉取当前规则。"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import ValidationError

from opti.configs.runtime import EDGE_RULES_KEY, EDGE_STATUS_KEY, HEARTBEAT_SECONDS, KeyValue
from opti.core.config import ProjectRules
from opti.sdk.models import utcnow

log = logging.getLogger("opti.config")
Fetch = Callable[[], Awaitable[tuple[int, str, dict[str, Any]] | None]]


def valkey_fetch(kv: KeyValue) -> Fetch:
    async def fetch() -> tuple[int, str, dict[str, Any]] | None:
        raw = await kv.get(EDGE_RULES_KEY)
        if raw is None:
            return None
        body = json.loads(raw)
        return int(body["version"]), str(body["digest"]), dict(body["rules"])

    return fetch


def gateway_fetch(client: Any) -> Fetch:
    async def fetch() -> tuple[int, str, dict[str, Any]] | None:
        digest, rules = await client.rules()
        return -1, digest, rules  # 网关不提供版本号

    return fetch


class EdgeRules:
    def __init__(
        self,
        rules: ProjectRules,
        fetch: Fetch,
        *,
        process: str,
        status: KeyValue | None = None,
        interval: float = 10.0,
    ) -> None:
        self.current = rules
        self._fetch = fetch
        self._process = process
        self._status = status
        self._interval = interval
        self._digest: str | None = None
        self._version = 0
        self._rejected: str | None = None
        self._error: str | None = None
        self._reported: float | None = None
        self._subscribers: list[Callable[[ProjectRules], None]] = []

    def subscribe(self, callback: Callable[[ProjectRules], None]) -> None:
        self._subscribers.append(callback)

    async def refresh(self) -> bool:
        try:
            got = await self._fetch()
        except Exception as e:
            log.warning("拉取规则失败，保留当前规则：%s", type(e).__name__)
            return False
        if got is None:
            return False
        version, digest, data = got
        # 只拒绝更旧的版本；同一版本号（纯文件规则恒为 0）由下面的 digest 判断是否变化。
        if version >= 0 and self._digest is not None and version < self._version:
            await self._report(force=False)
            return False
        if digest in (self._digest, self._rejected):
            await self._report(force=False)
            return False
        try:
            rules = ProjectRules.model_validate(data)
        except ValidationError as e:
            self._rejected = digest
            self._error = f"v{version}: {e.error_count()} 处校验错误"
            log.error("下发的规则无效，保留当前规则：%s", self._error)
            await self._report(force=True)
            return False
        self.current, self._digest, self._version, self._error = rules, digest, version, None
        for callback in list(self._subscribers):
            try:
                callback(rules)
            except Exception:
                log.exception("规则订阅回调失败")
        await self._report(force=True)
        return True

    async def _report(self, *, force: bool) -> None:
        if self._status is None:
            return
        now = time.monotonic()
        if not force and self._reported is not None and now - self._reported < HEARTBEAT_SECONDS:
            return
        body = json.dumps({
            "kind": "rules", "version": self._version, "digest": self._digest or "file",
            "error": self._error, "updated_at": utcnow().isoformat(),
        })  # fmt: skip
        try:
            await self._status.hset(EDGE_STATUS_KEY, self._process, body)
            self._reported = now
        except Exception:
            log.warning("上报规则状态失败", exc_info=True)

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            await self.refresh()
