"""总览仪表盘统计（设计文档 14）：一次查出页面所需的全部数字；只读数据库与已有缓存，不对外发请求。

计数、趋势与分布在数据库里聚合，只有超期与 Top 列表按 limit 取行（设计 2026-10-11）。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, Integer, Select, and_, case, distinct, func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.core.config import ProjectRules
from opti.db.models import Alert, AlertFinding, Entity, Finding, Takedown
from opti.pipeline import metrics
from opti.pipeline.reports import subject_of
from opti.takedown.hosting import load_host_data_many
from opti.takedown.stats import StatRow, compute

SLA_HOURS = {"critical": 4, "high": 24, "medium": 72}  # 设计文档 9.2
ACTIVE = ("open", "acknowledged")
SEVERITIES = ("critical", "high", "medium", "low")
TOP = 10
MAX_HOSTING = 300


def sla_hours() -> dict[str, int]:
    risk = policy.current().risk
    return {
        "critical": risk.sla_critical_hours,
        "high": risk.sla_high_hours,
        "medium": risk.sla_medium_hours,
    }


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


def _category_sql() -> ColumnElement[str]:
    """与 _category() 相同：开告警时冻结的类别优先。"""
    return func.coalesce(func.nullif(Alert.routing["category"].astext, ""), Finding.category)


def _score() -> ColumnElement[int]:
    """与 _brief() 相同：routing.score 是整数时取之，否则用发现的分数。"""
    raw = Alert.routing["score"]
    whole = and_(func.jsonb_typeof(raw) == "number", raw.astext.regexp_match(r"^-?[0-9]+$"))
    return case((whole, raw.astext.cast(Integer)), else_=Finding.score)


def _late(now: datetime) -> ColumnElement[Any]:
    """超期小时数（未定 SLA 的级别为 NULL）。"""
    return func.extract("epoch", literal(now) - Alert.created_at) / 3600 - case(
        *((Alert.severity == s, h) for s, h in sla_hours().items()), else_=None
    )


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
    cat = _category_sql()

    def alerts(*cols: Any) -> Select[Any]:
        stmt = (
            select(*cols)
            .select_from(Alert)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .join(Finding, Finding.id == AlertFinding.finding_id)
            .where(Alert.project_id == project)
        )
        return stmt.where(cat == category) if category else stmt

    opened = Alert.created_at >= since
    active = and_(Alert.status.in_(ACTIVE), Alert.ignored_at.is_(None))
    day = func.date(func.timezone("UTC", Alert.created_at))

    first_day = since.astimezone(UTC).date()
    trend: dict[date, Counter[str]] = {
        first_day + timedelta(days=i): Counter()
        for i in range((now.astimezone(UTC).date() - first_day).days + 1)
    }
    new_alerts = 0
    for d, severity, n in await session.execute(
        alerts(day, Alert.severity, func.count()).where(opened).group_by(day, Alert.severity)
    ):
        trend.setdefault(d, Counter())[severity] += n
        new_alerts += n
    by_category = [
        {"name": name, "count": n}
        for name, n in await session.execute(
            alerts(cat, func.count())
            .where(opened)
            .group_by(cat)
            .order_by(func.count().desc(), cat.collate("C"))
            .limit(20)
        )
    ]

    new_findings = await session.scalar(
        select(func.count())
        .select_from(Finding)
        .where(Finding.project_id == project, Finding.first_seen >= since)
    )
    per_finding = (
        select(Finding.id.label("finding_id"), func.unnest(Finding.sources).label("source"))
        .where(Finding.project_id == project, Finding.last_seen >= since)
        .subquery()
    )
    source_count = func.count(distinct(per_finding.c.finding_id))
    by_source = [
        {"name": name, "count": n}
        for name, n in await session.execute(
            select(per_finding.c.source, source_count)
            .group_by(per_finding.c.source)
            .order_by(source_count.desc(), per_finding.c.source.collate("C"))
            .limit(15)
        )
    ]

    late = _late(now)
    by_severity = alerts(Alert.severity, func.count()).where(active).group_by(Alert.severity)
    open_counts: dict[str, int] = {s: n for s, n in await session.execute(by_severity)}
    overdue_counts: dict[str, int] = {
        s: n for s, n in await session.execute(by_severity.where(late > 0))
    }
    briefs = (
        alerts(Alert, Finding, Entity).join(Entity, Entity.id == Finding.entity_id).where(active)
    )
    overdue = [
        _brief(a, f, e, overdue_hours=round((now - a.created_at).total_seconds() / 3600 - sla_hours()[a.severity], 1))
        for a, f, e in await session.execute(briefs.where(late > 0).order_by(late.desc(), Alert.id.desc()).limit(limit))
    ]  # fmt: skip
    top = [
        _brief(a, f, e)
        for a, f, e in await session.execute(briefs.order_by(_score().desc(), Alert.id.desc()).limit(limit))
    ]  # fmt: skip

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

    # 托管排行不受类别过滤：时间窗内高危告警的域名/URL 实体，最新告警优先，最多 MAX_HOSTING 个
    hosts = (
        await session.scalars(
            select(Entity)
            .join(Finding, Finding.entity_id == Entity.id)
            .join(AlertFinding, AlertFinding.finding_id == Finding.id)
            .join(Alert, Alert.id == AlertFinding.alert_id)
            .where(
                Alert.project_id == project,
                opened,
                Alert.severity.in_(("critical", "high")),
                Entity.type.in_(("domain", "url")),
            )
            .group_by(Entity.id)
            .order_by(func.max(Alert.created_at).desc(), Entity.id.desc())
            .limit(MAX_HOSTING)
        )
    ).all()
    countries: Counter[str] = Counter()
    networks: Counter[str] = Counter()
    for data in (
        await load_host_data_many(session, hosts)
    ).values():  # 只读 enrich_hosting 已有的缓存
        infos = [d for d in data.ips.values() if d]
        countries.update({str(d["country"]) for d in infos if d.get("country")})
        networks.update({str(d["network_name"]) for d in infos if d.get("network_name")})

    return {
        "days": days, "generated_at": now,
        "open_alerts": {s: open_counts.get(s, 0) for s in SEVERITIES},
        "new_alerts": new_alerts, "new_findings": int(new_findings or 0),
        "trend": [{"day": d.isoformat(), **{s: c.get(s, 0) for s in SEVERITIES}} for d, c in sorted(trend.items())],
        "by_category": by_category, "by_source": by_source,
        "mttd": [asdict(m) for m in await metrics.mttd(session, project, since=since, until=now)],
        "mttr_hours": mttr,
        "overdue": {s: overdue_counts.get(s, 0) for s in sla_hours()},
        "overdue_alerts": overdue, "top_alerts": top,
        "hosting_countries": _ranked(countries, TOP), "hosting_networks": _ranked(networks, TOP),
    }  # fmt: skip
