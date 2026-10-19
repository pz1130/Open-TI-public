"""日报、周报与月报的统计、生成与入库（设计文档 9.2、13、14）。"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.config import AlertingConfig
from opti.core.adjudication import TEXT_CATEGORIES
from opti.core.reports import empty_content, month_label
from opti.core.scoring import Severity, severity_rank
from opti.db.models import Alert, AlertFinding, Entity, Feedback, Finding, Report, Takedown

PERIODS = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
TOP = 20
MAX_ALERTS = 200
MONTHLY_EVENTS = 10
MONTHLY_TOP = 5
TREND_MONTHS = 6
MENTION_CATEGORIES = ("negative_press", "fraud_scam")


def period(kind: str, now: datetime) -> tuple[datetime, datetime]:
    end = now.replace(minute=0, second=0, microsecond=0)
    return end - PERIODS[kind], end


def _month_start(year: int, month: int, tz: ZoneInfo) -> datetime:
    year, month = year + (month - 1) // 12, (month - 1) % 12 + 1
    return datetime(year, month, 1, tzinfo=tz).astimezone(UTC)


def month_period(
    now: datetime, timezone: str, month: str | None = None
) -> tuple[datetime, datetime]:
    """报告时区下的自然月（UTC 起止）。不指定月份时取最近一个已结束的月份；指定的月份必须已结束。"""
    tz = ZoneInfo(timezone)
    if month is None:
        local = now.astimezone(tz)
        year, mon = local.year, local.month - 1
    else:
        m = re.fullmatch(r"(\d{4})-(0[1-9]|1[0-2])", month)
        if m is None:
            raise ValueError(f"月份格式应为 YYYY-MM：{month}")
        year, mon = int(m[1]), int(m[2])
    start, end = _month_start(year, mon, tz), _month_start(year, mon + 1, tz)
    if end > now:
        raise ValueError(f"{month} 尚未结束")
    return start, end


def subject_of(finding: Finding, entity_value: str) -> str:
    """告警的主题：文本类用标题，漏洞用 CVE 编号与名称，URL 类用 URL，其余用实体值（渲染时再去链接化）。"""
    m = finding.match
    doc = m.get("document")
    if finding.category in TEXT_CATEGORIES and isinstance(doc, dict) and doc.get("title"):
        return str(doc["title"])[:300]
    kev = m.get("kev")
    if finding.category == "vulnerability" and isinstance(kev, dict):
        return f"{kev.get('cve') or entity_value} {kev.get('name') or ''}".strip()[:300]
    url = m.get("url")
    return (url if isinstance(url, str) else entity_value)[:300]


def _alert_item(alert: Alert, finding: Finding, entity_value: str) -> dict[str, Any]:
    snap = alert.routing if isinstance(alert.routing, dict) else {}
    score = snap.get("score")
    return {
        "alert_id": alert.id, "severity": alert.severity, "category": str(snap.get("category") or finding.category),
        "subject": subject_of(finding, entity_value), "score": score if isinstance(score, int) else finding.score,
    }  # fmt: skip


async def _latest_alerts(session: AsyncSession, finding_ids: Sequence[int]) -> dict[int, int]:
    if not finding_ids:
        return {}
    rows = await session.execute(
        select(AlertFinding.finding_id, func.max(AlertFinding.alert_id))
        .where(AlertFinding.finding_id.in_(list(finding_ids)))
        .group_by(AlertFinding.finding_id)
    )
    return {int(f): int(a) for f, a in rows.all()}


def _llm(finding: Finding) -> dict[str, Any]:
    raw = finding.match.get("llm")
    return raw if isinstance(raw, dict) else {}


def _news_item(f: Finding, latest: dict[int, int]) -> dict[str, Any]:
    raw_doc = f.match.get("document")
    doc = raw_doc if isinstance(raw_doc, dict) else {}
    return {
        "finding_id": f.id, "alert_id": latest.get(f.id), "category": f.category,
        "title": str(doc.get("title") or "")[:300], "url": doc.get("url") if isinstance(doc.get("url"), str) else None,
        "source": str(doc.get("source_name") or "")[:200], "summary": str(_llm(f).get("summary") or "")[:500],
        "score": f.score,
    }  # fmt: skip


def _vuln_item(f: Finding, latest: dict[int, int]) -> dict[str, Any]:
    raw_kev = f.match.get("kev")
    kev = raw_kev if isinstance(raw_kev, dict) else {}
    software = [s for s in f.match.get("software") or [] if isinstance(s, dict)]
    return {
        "finding_id": f.id, "alert_id": latest.get(f.id), "cve": str(kev.get("cve") or ""),
        "name": str(kev.get("name") or ""), "severity": f.severity, "score": f.score,
        "software": [f"{s.get('vendor') or ''} {' / '.join(s.get('products') or [])}".strip() for s in software],
    }  # fmt: skip


async def build(
    session: AsyncSession,
    kind: str,
    *,
    project: str,
    start: datetime,
    end: datetime,
    cfg: AlertingConfig,
) -> dict[str, Any]:
    content = empty_content(
        kind, start=start, end=end, language=cfg.report_language, timezone=cfg.report_timezone
    )
    findings = (
        await session.execute(
            select(Finding, Entity.value)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(
                Finding.project_id == project, Finding.first_seen >= start, Finding.first_seen < end
            )
        )
    ).all()
    alert_q = (
        select(Alert, Finding, Entity.value)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .join(Entity, Entity.id == Finding.entity_id)
        .where(Alert.project_id == project)
    )
    opened = (
        await session.execute(alert_q.where(Alert.created_at >= start, Alert.created_at < end))
    ).all()
    sev = Counter(a.severity for a, _, _ in opened)
    content["totals"] = {
        "findings": len(findings), "alerts": len(opened), "critical": sev["critical"], "high": sev["high"],
        "medium": sev["medium"], "low": sum(f.severity == "low" for f, _ in findings),
    }  # fmt: skip
    by_f = Counter(f.category for f, _ in findings)
    by_a = Counter(_alert_item(a, f, v)["category"] for a, f, v in opened)
    content["by_category"] = [
        {"category": c, "findings": by_f[c], "alerts": by_a[c]}
        for c in sorted(set(by_f) | set(by_a), key=lambda c: (-by_f[c], -by_a[c], c))
    ]
    if kind == "daily":
        pending = (
            await session.execute(
                alert_q.where(
                    Alert.status.in_(("open", "acknowledged")),
                    Alert.digest_sent_at.is_(None),
                    Alert.ignored_at.is_(None),
                    Alert.severity.in_([s.value for s in cfg.digest]),
                )
                .order_by(Alert.id)
                .limit(MAX_ALERTS)
            )
        ).all()
        content["alerts"] = [_alert_item(a, f, v) for a, f, v in pending]
    else:
        ranked = sorted(
            (x for x in opened if x[0].severity in ("critical", "high", "medium")),
            key=lambda x: (-severity_rank(Severity(x[0].severity)), -x[1].score, x[0].id),
        )
        content["alerts"] = [_alert_item(a, f, v) for a, f, v in ranked[:MAX_ALERTS]]
    news_rows = (
        await session.scalars(
            select(Finding)
            .where(
                Finding.project_id == project,
                Finding.category.in_(sorted(TEXT_CATEGORIES)),
                Finding.last_seen >= start,
                Finding.last_seen < end,
            )
            .order_by(Finding.score.desc(), Finding.id)
            .limit(TOP * 3)
        )
    ).all()
    news = [f for f in news_rows if _llm(f).get("verdict") != "no"][
        :TOP
    ]  # 模型判为「不是本机构」的不进报告
    vulns = (
        await session.scalars(
            select(Finding)
            .where(
                Finding.project_id == project,
                Finding.category == "vulnerability",
                Finding.first_seen >= start,
                Finding.first_seen < end,
            )
            .order_by(Finding.score.desc(), Finding.id)
            .limit(TOP)
        )
    ).all()
    latest = await _latest_alerts(session, [f.id for f in [*news, *vulns]])
    content["news"] = [_news_item(f, latest) for f in news]
    content["vulnerabilities"] = [_vuln_item(f, latest) for f in vulns]
    if kind == "weekly":
        lows = sorted(
            (x for x in findings if x[0].severity == "low"), key=lambda x: (-x[0].score, x[0].id)
        )
        content["low"] = {
            "count": len(lows),
            "top": [
                {
                    "finding_id": f.id,
                    "category": f.category,
                    "subject": subject_of(f, v),
                    "score": f.score,
                }
                for f, v in lows[:10]
            ],
        }
        verdicts = await session.execute(
            select(Feedback.verdict, func.count())
            .join(Finding, Finding.id == Feedback.finding_id)
            .where(
                Finding.project_id == project,
                Feedback.created_at >= start,
                Feedback.created_at < end,
            )
            .group_by(Feedback.verdict)
        )
        content["triage"] = {str(v): int(n) for v, n in verdicts.all()}
        opened_td = await session.scalar(
            select(func.count()).select_from(Takedown)
            .where(Takedown.project_id == project, Takedown.created_at >= start, Takedown.created_at < end)
        )  # fmt: skip
        resolved_td = await session.scalar(
            select(func.count()).select_from(Takedown)
            .where(Takedown.project_id == project, Takedown.resolved_at >= start, Takedown.resolved_at < end)
        )  # fmt: skip
        content["takedowns"] = {"opened": int(opened_td or 0), "resolved": int(resolved_td or 0)}
    return content


async def _alert_severities(
    session: AsyncSession, project: str, start: datetime, end: datetime
) -> Counter[str]:
    rows = await session.execute(
        select(Alert.severity, func.count())
        .where(Alert.project_id == project, Alert.created_at >= start, Alert.created_at < end)
        .group_by(Alert.severity)
    )
    return Counter({str(s): int(n) for s, n in rows.all()})


async def _totals(
    session: AsyncSession, project: str, start: datetime, end: datetime
) -> dict[str, int]:
    rows = await session.execute(
        select(Finding.severity, func.count())
        .where(Finding.project_id == project, Finding.first_seen >= start, Finding.first_seen < end)
        .group_by(Finding.severity)
    )
    found = {str(s): int(n) for s, n in rows.all()}
    alerts = await _alert_severities(session, project, start, end)
    return {
        "findings": sum(found.values()), "alerts": alerts.total(), "critical": alerts["critical"],
        "high": alerts["high"], "medium": alerts["medium"], "low": found.get("low", 0),
    }  # fmt: skip


async def _alert_categories(
    session: AsyncSession, project: str, start: datetime, end: datetime
) -> Counter[str]:
    category = func.coalesce(Alert.routing["category"].astext, Finding.category)  # 与告警快照一致
    rows = await session.execute(
        select(category, func.count(func.distinct(Alert.id)))
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .where(Alert.project_id == project, Alert.created_at >= start, Alert.created_at < end)
        .group_by(category)
    )
    return Counter({str(c): int(n) for c, n in rows.all()})


async def _ranked_findings(session: AsyncSession, *conditions: Any) -> tuple[int, list[Finding]]:
    total = await session.scalar(select(func.count()).select_from(Finding).where(*conditions))
    top = (
        await session.scalars(
            select(Finding)
            .where(*conditions)
            .order_by(Finding.score.desc(), Finding.id)
            .limit(MONTHLY_TOP)
        )
    ).all()
    return int(total or 0), list(top)


async def build_monthly(
    session: AsyncSession, *, project: str, start: datetime, end: datetime, cfg: AlertingConfig
) -> dict[str, Any]:
    """月报（面向管理层）：本月与上月对比、重点事件、漏洞与舆情摘要、近 6 个月告警趋势。"""
    tz = ZoneInfo(cfg.report_timezone)
    content = empty_content(
        "monthly", start=start, end=end, language=cfg.report_language, timezone=cfg.report_timezone
    )
    local = start.astimezone(tz)
    prev_start = _month_start(local.year, local.month - 1, tz)
    content["totals"] = await _totals(session, project, start, end)
    content["previous"] = await _totals(session, project, prev_start, start)
    now_c, prev_c = (
        await _alert_categories(session, project, start, end),
        await _alert_categories(session, project, prev_start, start),
    )
    content["by_category"] = [
        {"category": c, "alerts": now_c[c], "previous": prev_c[c]}
        for c in sorted(set(now_c) | set(prev_c), key=lambda c: (-now_c[c], -prev_c[c], c))
    ]
    opened = (
        await session.execute(
            select(Alert, Finding, Entity.value)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .join(Finding, Finding.id == AlertFinding.finding_id)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(
                Alert.project_id == project, Alert.created_at >= start, Alert.created_at < end,
                Alert.severity.in_(("critical", "high")),
            )
        )
    ).all()  # fmt: skip
    seen: set[int] = set()
    events: list[tuple[Alert, Finding, str]] = []
    for a, f, v in sorted(
        opened, key=lambda x: (-severity_rank(Severity(x[0].severity)), -x[1].score, x[0].id)
    ):
        if a.id not in seen and len(events) < MONTHLY_EVENTS:
            seen.add(a.id)
            events.append((a, f, v))
    rows = await session.execute(
        select(Takedown.alert_id, Takedown.state)
        .where(Takedown.alert_id.in_([a.id for a, _, _ in events]))
        .order_by(Takedown.id)  # 同一告警有多次投诉时，取最近一次
    )
    takedowns = {int(alert_id): str(state) for alert_id, state in rows.all()}
    content["alerts"] = [
        {**_alert_item(a, f, v), "status": a.status, "verdict": a.triage_verdict, "takedown": takedowns.get(a.id)}
        for a, f, v in events
    ]  # fmt: skip
    in_month = (
        Finding.project_id == project,
        Finding.first_seen >= start,
        Finding.first_seen < end,
    )
    verdict = Finding.match["llm"]["verdict"].astext
    n_news, news = await _ranked_findings(
        session, *in_month, Finding.category.in_(MENTION_CATEGORIES),
        or_(verdict.is_(None), verdict != "no"),  # 模型判为「不是本机构」的不计入
    )  # fmt: skip
    n_vulns, vulns = await _ranked_findings(session, *in_month, Finding.category == "vulnerability")
    latest = await _latest_alerts(session, [f.id for f in [*news, *vulns]])
    content["news"] = [_news_item(f, latest) for f in news]
    content["vulnerabilities"] = [_vuln_item(f, latest) for f in vulns]
    content["counts"] = {"news": n_news, "vulnerabilities": n_vulns}
    content["trend"] = []
    for back in range(TREND_MONTHS - 1, -1, -1):
        m_start = _month_start(local.year, local.month - back, tz)
        m_end = _month_start(local.year, local.month - back + 1, tz)
        sev = await _alert_severities(session, project, m_start, m_end)
        content["trend"].append(
            {
                "month": month_label(m_start, tz),
                "critical": sev["critical"],
                "high": sev["high"],
                "medium": sev["medium"],
            }
        )
    return content


async def generate(
    session: AsyncSession,
    kind: str,
    *,
    project: str,
    cfg: AlertingConfig,
    now: datetime,
    month: str | None = None,
) -> Report:
    """生成并保存报告；同一类型、同一周期只生成一份。日报给收入的告警盖 digest_sent_at。

    月报按报告时区的自然月统计，``month``（YYYY-MM）用于补生成，缺省为最近一个已结束的月份。
    """
    if kind == "monthly":
        start, end = month_period(now, cfg.report_timezone, month)
    else:
        start, end = period(kind, now)
    existing = await session.scalar(
        select(Report).where(
            Report.project_id == project, Report.kind == kind, Report.period_end == end
        )
    )
    if existing is not None:
        return existing
    if kind == "monthly":
        content = await build_monthly(session, project=project, start=start, end=end, cfg=cfg)
    else:
        content = await build(session, kind, project=project, start=start, end=end, cfg=cfg)
    row = Report(
        project_id=project, kind=kind, period_start=start, period_end=end, created_at=now,
        language=cfg.report_language, content=content, sent_sinks=[],
    )  # fmt: skip
    session.add(row)
    await session.flush()
    ids = [a["alert_id"] for a in content["alerts"]] if kind == "daily" else []
    if ids:
        await session.execute(update(Alert).where(Alert.id.in_(ids)).values(digest_sent_at=now))
    return row
