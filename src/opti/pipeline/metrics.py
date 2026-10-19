"""MTTD 样本（设计文档 1.4）：每个发现的第一条告警，以最早一次观测的来源事件时间为起点。

样本在第一条告警打开时算出并存到 finding（repo.open_alert 调用 record_sample），
存量由 opti db-upgrade 调用 backfill_samples 补算；mttd() 只做 SQL 聚合。
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Float, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.metrics import (
    MttdStat,
    ct_event_time,
    registration_time,
    source_group,
    target_hours,
)
from opti.db.models import Alert, AlertFinding, Entity, Finding, FindingObservation, RawItemRow

DOMAIN_CATEGORIES = ("typosquat_domain", "phishing_site")
MTTD_QUERY_BATCH = 1_000  # asyncpg 最多接收 32,767 个查询参数

Case = tuple[Finding, Entity | None, datetime]  # 发现、其实体、第一条告警时间


async def compute_samples(
    session: AsyncSession, cases: Sequence[Case]
) -> dict[int, tuple[str, float]]:
    """返回 {finding_id: (来源组, 小时数)}；来源不计或缺起点时间（原始数据已清理、缺字段）的不在结果里。"""
    first_obs: dict[int, FindingObservation] = {}
    finding_ids = [f.id for f, _, _ in cases]
    for offset in range(0, len(finding_ids), MTTD_QUERY_BATCH):
        for row in await session.scalars(
            select(FindingObservation)
            .where(
                FindingObservation.finding_id.in_(finding_ids[offset : offset + MTTD_QUERY_BATCH])
            )
            .order_by(
                FindingObservation.finding_id, FindingObservation.observed_at, FindingObservation.id
            )
        ):
            first_obs.setdefault(row.finding_id, row)
    ct_items = [o.item_id for o in first_obs.values() if source_group(o.connector_id) == "ct"]
    payloads: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(ct_items), MTTD_QUERY_BATCH):
        payloads.update(
            (
                await session.execute(
                    select(RawItemRow.item_id, RawItemRow.payload).where(
                        RawItemRow.item_id.in_(ct_items[offset : offset + MTTD_QUERY_BATCH])
                    )
                )
            ).all()
        )
    out: dict[int, tuple[str, float]] = {}
    for finding, entity, alerted_at in cases:
        obs = first_obs.get(finding.id)
        group = source_group(obs.connector_id) if obs is not None else None
        if obs is None or group is None:
            continue
        if group == "ct":
            start = ct_event_time(obs.connector_id, payloads.get(obs.item_id) or {})
        else:
            start = registration_time((entity.enrichment if entity is not None else None) or {})
        if start is None:
            continue
        out[finding.id] = (group, round(max((alerted_at - start).total_seconds(), 0.0) / 3600, 4))
    return out


async def record_sample(
    session: AsyncSession, finding: Finding, entity: Entity | None, now: datetime
) -> None:
    """开告警时调用：第一次记下告警时间并算样本；之前缺样本的（如当时没有 RDAP）按原告警时间重算。"""
    if finding.first_alerted_at is None:
        finding.first_alerted_at = now
    elif finding.mttd_hours is not None:
        return
    sample = (await compute_samples(session, [(finding, entity, finding.first_alerted_at)])).get(
        finding.id
    )
    if sample is not None:
        finding.mttd_source, finding.mttd_hours = sample


async def backfill_samples(session: AsyncSession) -> int:
    """给有告警但 first_alerted_at 为空的发现补时间与样本，每批提交一次；返回补算的发现数。可重复运行。"""
    first_alert = (
        select(AlertFinding.finding_id, func.min(Alert.created_at).label("alerted_at"))
        .join(Alert, Alert.id == AlertFinding.alert_id)
        .group_by(AlertFinding.finding_id)
        .subquery()
    )
    total = 0
    while True:
        rows = (
            await session.execute(
                select(Finding, Entity, first_alert.c.alerted_at)
                .join(first_alert, first_alert.c.finding_id == Finding.id)
                .outerjoin(Entity, Entity.id == Finding.entity_id)
                .where(Finding.first_alerted_at.is_(None))
                .order_by(Finding.id)
                .limit(MTTD_QUERY_BATCH)
            )
        ).all()
        if not rows:
            return total
        cases = [(f, e, t) for f, e, t in rows]
        samples = await compute_samples(session, cases)
        for finding, _, alerted_at in cases:
            finding.first_alerted_at = alerted_at
            if finding.id in samples:
                finding.mttd_source, finding.mttd_hours = samples[finding.id]
        await session.commit()
        total += len(cases)


async def mttd(
    session: AsyncSession, project: str, *, since: datetime, until: datetime
) -> list[MttdStat]:
    target = case(
        *((Finding.mttd_source == src, hours) for src, hours in target_hours().items()),
        else_=None,
    )
    rows = (
        await session.execute(
            select(
                Finding.mttd_source,
                func.count(),
                func.percentile_cont(0.5).within_group(Finding.mttd_hours),
                func.avg(case((Finding.mttd_hours < target, 1.0), else_=0.0).cast(Float)),
            )
            .where(
                Finding.project_id == project,
                Finding.first_alerted_at >= since,
                Finding.first_alerted_at < until,
                Finding.category.in_(DOMAIN_CATEGORIES),
                Finding.mttd_hours.is_not(None),
            )
            .group_by(Finding.mttd_source)
        )
    ).all()
    found = {src: (int(n), float(med), float(within)) for src, n, med, within in rows}
    out = []
    for source, hours in target_hours().items():
        if source in found:
            n, med, within = found[source]
            out.append(MttdStat(source, n, round(med, 2), round(within, 3), hours))
        else:
            out.append(MttdStat(source, 0, None, None, hours))
    return out
