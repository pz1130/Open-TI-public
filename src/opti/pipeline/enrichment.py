"""富化调度与缓存（设计文档 10.1）：结果按实体缓存，TTL 内不重复调用，节省第三方额度。"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from opti.core import policy
from opti.core.codehits import sanitize_scan_result
from opti.db.models import Entity
from opti.sdk.base import Enricher
from opti.storage.artifacts import ArtifactSaver, offload_artifacts

Clock = Callable[[], datetime]
DEFAULT_TIMEOUT = 120.0  # 单个富化器的总时长上限（富化在处理事务内执行，不能无限占用连接）


def utcnow() -> datetime:
    return datetime.now(UTC)


# 会真正打开目标页面的富化器；平台名单内的主机一律不访问（设计文档 4.2，平台条款禁止自动访问）
VISITING = frozenset({"http_probe", "screenshot"})


class EnrichmentService:
    def __init__(
        self,
        enrichers: Mapping[str, Enricher],
        *,
        clock: Clock = utcnow,
        timeout: float = DEFAULT_TIMEOUT,
        saver: ArtifactSaver | None = None,
        no_visit: Callable[[str], bool] | None = None,
    ) -> None:
        self._enrichers = dict(enrichers)
        self._no_visit = no_visit
        self._clock = clock
        self._timeout = timeout
        self._saver = saver
        self._log = logging.getLogger("opti.enrichment")

    @property
    def available(self) -> tuple[str, ...]:
        return tuple(sorted(self._enrichers))

    def get(self, eid: str) -> Enricher | None:
        return self._enrichers.get(eid)

    def visit_allowed(self, type_: str, value: str) -> bool:
        """目标页面能否访问：主机属于平台名单（如 linkedin.com、t.me）时不能。"""
        if self._no_visit is None:
            return True
        try:
            host = urlsplit(value).hostname if type_ == "url" else value
        except ValueError:
            return False
        return not (host and self._no_visit(host.lower().rstrip(".")))

    @staticmethod
    def _data(cached: Any) -> dict[str, Any]:
        return dict(cached.get("data") or {}) if isinstance(cached, dict) else {}

    @staticmethod
    def _fresh(cached: Any, max_age: timedelta, now: datetime) -> bool:
        if not isinstance(cached, dict):
            return False
        try:
            fetched = datetime.fromisoformat(str(cached["fetched_at"]))
        except (KeyError, ValueError):
            return False
        return now - fetched < max_age

    async def enrich(
        self,
        entity: Entity,
        ids: Sequence[str],
        *,
        force: bool = False,
        targets: Mapping[str, tuple[str, str]] | None = None,
    ) -> dict[str, dict[str, Any]]:
        now = self._clock()
        cache: dict[str, Any] = dict(entity.enrichment or {})
        out: dict[str, dict[str, Any]] = {}
        for eid in ids:
            enricher = self._enrichers.get(eid)
            type_, value = (targets or {}).get(eid, (entity.type, entity.value))
            if enricher is None or not enricher.supports(type_):
                continue
            if eid in VISITING and not self.visit_allowed(type_, value):
                continue
            cached = cache.get(eid)
            # Never score a phishing path using a homepage/other-path cache.
            if isinstance(cached, dict) and (
                cached.get("target_type", entity.type) != type_
                or cached.get("target_value", entity.value) != value
            ):
                cached = None
            ttl = timedelta(seconds=enricher.cache_ttl_seconds)
            if not force and self._fresh(cached, ttl, now):
                out[eid] = self._data(cached)
                continue
            try:
                data = await asyncio.wait_for(enricher.enrich(type_, value), self._timeout)
            except Exception as e:  # 富化器的缺陷、超时或第三方故障不能中断流水线（设计文档 5.4）
                self._log.warning("富化器 %s 处理 %s 失败：%s", eid, entity.value, e)
                data = {"error": type(e).__name__}
            if eid == "secret_scan":
                data = sanitize_scan_result(data, value, now)
            if not data.get("error"):
                # 截图等产物先写入对象存储，只缓存引用（base64 不能进 entity.enrichment）
                try:
                    data = await offload_artifacts(data, self._saver)
                except Exception as e:  # 对象存储故障不能中断流水线
                    self._log.warning("富化器 %s 的产物保存失败：%s", eid, type(e).__name__)
                    data = {"error": "ArtifactStoreError"}
            # error 为 None 的成功结果（例如 DNS）仍缓存；超时等失败不能占满 TTL。
            if data.get("error"):
                # 偶发失败沿用近期成功结果，避免分数抖动造成重复告警；强制刷新（监视复查）要看到真实失败。
                stale = not force and self._fresh(
                    cached, timedelta(hours=policy.current().scanning.stale_if_error_hours), now
                )
                out[eid] = self._data(cached) if stale else data
                continue
            cache[eid] = {"data": data, "fetched_at": now.isoformat()}
            if (type_, value) != (entity.type, entity.value):
                cache[eid].update(target_type=type_, target_value=value)
            out[eid] = data
        entity.enrichment = cache  # 重新赋值，确保 SQLAlchemy 检测到 JSONB 变化
        return out
