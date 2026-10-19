"""境内分派（设计文档 3.4、5.4）：境外富化器的远程代理；境外连接器的运行下发与超时清理。"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, ClassVar, cast

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.cursors import PgCursorStore
from opti.db.models import ConnectorRun
from opti.gateway.jobs import Job, JobQueue
from opti.gateway.records import ACTIVE_RUN
from opti.sdk.base import Enricher
from opti.sdk.models import Tier
from opti.sdk.scan import KeywordScan, node_rules_for_scan

log = logging.getLogger("opti.dispatch")
DEFAULT_MAX_RUNTIME = 3600.0


class RemoteEnricher(Enricher):
    """把富化调用变成网关任务，由采集节点执行，境内同步等待结果。"""

    id: ClassVar[str] = "remote"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ()

    def __init__(self, jobs: JobQueue, *, timeout: float) -> None:
        # 不调用基类构造：境内没有这个富化器的上下文与 HTTP 客户端，请求在采集节点上发出
        self.config: dict[str, Any] = {}
        self._jobs = jobs
        self._timeout = timeout

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        payload = {"enricher": self.id, "type": entity_type, "value": value}
        job = Job.new("enrich", payload, ttl=self._timeout, reply=True)
        await self._jobs.submit(job)
        result = await self._jobs.wait(job.id, self._timeout)
        return result if result is not None else {"error": "RemoteTimeout"}


def remote_enricher(cls: type[Enricher], jobs: JobQueue, *, timeout: float) -> RemoteEnricher:
    sub = type(
        f"Remote_{cls.id}",
        (RemoteEnricher,),
        {
            "id": cls.id,
            "tier": cls.tier,
            "supported_types": cls.supported_types,
            "cache_ttl_seconds": cls.cache_ttl_seconds,
        },
    )
    return cast(RemoteEnricher, sub(jobs, timeout=timeout))


async def dispatch_connector_run(
    session: AsyncSession,
    jobs: JobQueue,
    connector_id: str,
    *,
    now: datetime,
    max_items: int | None = None,
    seconds: float | None = None,
    max_runtime: float = DEFAULT_MAX_RUNTIME,
    scan: KeywordScan | None = None,
    rules: ProjectRules | None = None,
) -> int | None:
    # 同一连接器同时只下发一个运行（定时任务重叠或手动触发）
    await session.execute(
        select(func.pg_advisory_xact_lock(func.hashtext(f"opti.run:{connector_id}")))
    )
    active = await session.scalar(
        select(ConnectorRun.id)
        .where(ConnectorRun.connector_id == connector_id, ConnectorRun.status.in_(ACTIVE_RUN))
        .limit(1)
    )
    if active is not None:
        log.info("连接器 %s 上一次运行（%s）尚未结束，本次不下发", connector_id, active)
        return None
    cursors = PgCursorStore()
    await cursors.load(session, connector_id)
    run = ConnectorRun(
        connector_id=connector_id,
        started_at=now,
        status="dispatched",
        items=0,
        errors=0,
        message="",
        deadline_at=now + timedelta(seconds=max_runtime),
    )
    session.add(run)
    await session.flush()
    payload = {
        "run_id": run.id,
        "connector_id": connector_id,
        "cursors": cursors.dump(connector_id),
        "max_items": max_items,
        "seconds": seconds,
    }
    if scan is not None:
        if rules is None:
            raise ValueError("manual scan requires its rules snapshot")
        payload["keyword_scan"] = {
            "scan": scan.model_dump(mode="json"),
            "rules": node_rules_for_scan(rules),
        }
    await jobs.submit(Job.new("run_connector", payload, ttl=max_runtime))
    return run.id


async def sweep_stale_runs(session: AsyncSession, now: datetime) -> int:
    """采集节点在期限内没有回报的运行判为失败；游标没有写回，下一个周期从原位置重新采集。"""
    result = await session.execute(
        update(ConnectorRun)
        .where(ConnectorRun.status.in_(ACTIVE_RUN), ConnectorRun.deadline_at < now)
        .values(
            status="error",
            errors=1,
            ended_at=now,
            message="timeout：采集节点未在期限内回报结果",
        )
        .returning(ConnectorRun.id)
    )
    return len(result.all())
