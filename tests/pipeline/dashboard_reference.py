"""等价性测试的参照答案：2026-10-11 改 SQL 聚合前的 opti.pipeline.dashboard.build，原样保留，不要修改。

与新实现共用 metrics.mttd 与 load_host_data；托管排行在少于 MAX_HOSTING 个主机时与新实现一致。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Alert, AlertFinding, Entity, Finding, Takedown
from opti.pipeline import metrics
from opti.pipeline.reports import subject_of
from opti.takedown.hosting import load_host_data
from opti.takedown.stats import StatRow, compute

SLA_HOURS = {"critical": 4, "high": 24, "medium": 72}  # 设计文档 9.2
ACTIVE = ("open", "acknowledged")
SEVERITIES = ("critical", "high", "medium", "low")
TOP = 10
MAX_HOSTING = 300


def _category(alert: Alert, finding: Finding) -> str:
    """开告警时冻结的类别优先（分析员人工提交可能改过类别）。"""
    snap = alert.routing if isinstance(alert.routing, dict) else {}
    return str(snap.get("category") or finding.category)


def _brief(
    alert: Alert, finding: Finding, entity: Entity, *, overdue_hours: float | None = None
) -> dict[str, Any]:
    snap = alert.routing if isinstance(alert.routing, dict) else {}
    score = snap.get("score")
    return {
        "alert_id": alert.id, "severity": alert.severity, "category": _category(alert, finding),
        "subject": subject_of(finding, entity.value), "score": score if isinstance(score, int) else finding.score,
        "created_at": alert.created_at, "overdue_hours": overdue_hours,
    }  # fmt: skip


def _ranked(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [
        {"name": k, "count": v}
        for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    ]


async def build(
    session: AsyncSession,
    rules: ProjectRules,
    *,
    now: datetime,
    days: int,
    category: str | None = None,
    limit: int = TOP,
) -> dict[str, Any]:
    """category 只过滤告警相关部分（数量、趋势、类别分布、超期与 Top 列表）；
    发现数、来源贡献、MTTD、MTTR 与托管排行不受影响。limit 控制超期与 Top 列表条数。"""
    project = rules.project
    since = now - timedelta(days=days)
    joined = (
        select(Alert, Finding, Entity)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .join(Entity, Entity.id == Finding.entity_id)
        .where(Alert.project_id == project)
    )
    opened_all = (await session.execute(joined.where(Alert.created_at >= since))).all()
    active = (await session.execute(joined.where(Alert.status.in_(ACTIVE)))).all()
    opened = opened_all
    if category:
        opened = [r for r in opened_all if _category(r[0], r[1]) == category]
        active = [r for r in active if _category(r[0], r[1]) == category]

    first_day = since.astimezone(UTC).date()
    trend: dict[date, Counter[str]] = {
        first_day + timedelta(days=i): Counter()
        for i in range((now.astimezone(UTC).date() - first_day).days + 1)
    }
    for a, _, _ in opened:
        trend.setdefault(a.created_at.astimezone(UTC).date(), Counter())[a.severity] += 1
    by_category = Counter(_category(a, f) for a, f, _ in opened)

    new_findings = await session.scalar(
        select(func.count())
        .select_from(Finding)
        .where(Finding.project_id == project, Finding.first_seen >= since)
    )
    sources: Counter[str] = Counter()
    for srcs in await session.scalars(
        select(Finding.sources).where(Finding.project_id == project, Finding.last_seen >= since)
    ):
        sources.update(set(srcs or []))

    open_counts = Counter(a.severity for a, _, _ in active)
    overdue = []
    for a, f, e in active:
        sla = SLA_HOURS.get(a.severity)
        late = (now - a.created_at).total_seconds() / 3600 - sla if sla is not None else 0
        if late > 0:
            overdue.append(_brief(a, f, e, overdue_hours=round(late, 1)))
    overdue.sort(key=lambda x: -float(x["overdue_hours"]))
    top = sorted(
        (_brief(a, f, e) for a, f, e in active),
        key=lambda x: (-int(x["score"]), -int(x["alert_id"])),
    )

    takedowns = (
        await session.execute(
            select(Takedown, Finding.first_seen)
            .join(Finding, Finding.id == Takedown.finding_id)
            .where(Takedown.project_id == project, Takedown.created_at >= since)
        )
    ).all()
    mttr = compute(
        [
            StatRow(td.state, str(td.target.get("name") or ""), str(td.target.get("kind") or ""),
                    td.submitted_at, td.acknowledged_at, td.resolved_at, first_seen)
            for td, first_seen in takedowns
        ]
    )["mttr_hours"]  # fmt: skip

    countries: Counter[str] = Counter()
    networks: Counter[str] = Counter()
    hosts: set[int] = set()
    for a, _, e in opened_all:
        if (
            a.severity not in ("critical", "high")
            or e.type not in ("domain", "url")
            or e.id in hosts
        ):
            continue
        if len(hosts) >= MAX_HOSTING:
            break
        hosts.add(e.id)
        data = await load_host_data(session, e)  # 只读 enrich_hosting 已有的缓存
        infos = [d for d in data.ips.values() if d]
        countries.update({str(d["country"]) for d in infos if d.get("country")})
        networks.update({str(d["network_name"]) for d in infos if d.get("network_name")})

    return {
        "days": days, "generated_at": now,
        "open_alerts": {s: open_counts.get(s, 0) for s in SEVERITIES},
        "new_alerts": len(opened), "new_findings": int(new_findings or 0),
        "trend": [{"day": d.isoformat(), **{s: c.get(s, 0) for s in SEVERITIES}} for d, c in sorted(trend.items())],
        "by_category": _ranked(by_category, 20), "by_source": _ranked(sources, 15),
        "mttd": [asdict(m) for m in await metrics.mttd(session, project, since=since, until=now)],
        "mttr_hours": mttr,
        "overdue": {s: sum(o["severity"] == s for o in overdue) for s in SLA_HOURS},
        "overdue_alerts": overdue[:limit], "top_alerts": top[:limit],
        "hosting_countries": _ranked(countries, TOP), "hosting_networks": _ranked(networks, TOP),
    }  # fmt: skip
