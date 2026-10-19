from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.config import AlertingConfig
from opti.api import security
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, severity_for
from opti.db import repo
from opti.db.models import Alert, Report, Takedown
from opti.pipeline import reports

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 1, 30, tzinfo=UTC)
CFG = AlertingConfig(public_base_url="https://ti.example")
DOC = {
    "document": {
        "title": "Bank approves loan",
        "url": "https://news.example/a",
        "source_name": "Example News",
    }
}


async def _seed(session: AsyncSession, rules: ProjectRules, etype: str, value: str, category: str, score: int,
                match: dict[str, Any], *, when: datetime, alert: bool = False) -> tuple[int, int | None]:  # fmt: skip
    await repo.upsert_project(session, rules)
    entity = await repo.upsert_entity(session, etype, value, when)
    s = Score(score, severity_for(score), Category(category), {"base": score})
    up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=s, match=match,
                                   source="test", now=when)  # fmt: skip
    alert_id = (await repo.open_alert(session, up.finding, s.severity, when)).id if alert else None
    return up.finding.id, alert_id


async def _world(session: AsyncSession, rules: ProjectRules) -> dict[str, Any]:
    recent, old = NOW - timedelta(hours=3), NOW - timedelta(days=2)
    ids: dict[str, Any] = {}
    ids["old"] = await _seed(
        session, rules, "domain", "sbr-older.top", "typosquat_domain", 50, {}, when=old, alert=True
    )
    ids["medium"] = await _seed(
        session,
        rules,
        "domain",
        "sbr-portal.top",
        "typosquat_domain",
        50,
        {},
        when=recent,
        alert=True,
    )
    ids["high"] = await _seed(session, rules, "url", "https://sbr-loans.com/login", "phishing_site", 80,
                              {"url": "https://sbr-loans.com/login"}, when=recent, alert=True)  # fmt: skip
    ids["news"] = await _seed(session, rules, "document", "cluster:1", "brand_mention", 25,
                              {**DOC, "llm": {"verdict": "yes", "summary": "批准贷款"}}, when=recent)  # fmt: skip
    ids["noise"] = await _seed(session, rules, "document", "cluster:2", "brand_mention", 20,
                               {**DOC, "llm": {"verdict": "no"}}, when=recent)  # fmt: skip
    kev = {"kev": {"cve": "CVE-2026-12345", "name": "EdgeGate VPN Bypass"},
           "software": [{"vendor": "Example Networks", "products": ["EdgeGate VPN"]}]}  # fmt: skip
    ids["vuln"] = await _seed(
        session, rules, "cve", "CVE-2026-12345", "vulnerability", 55, kev, when=recent, alert=True
    )
    ids["low"] = await _seed(
        session, rules, "domain", "sbr-low.top", "typosquat_domain", 25, {}, when=recent
    )
    return ids


async def test_daily_report(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    ids = await _world(session, sbr_rules)
    row = await reports.generate(session, "daily", project=sbr_rules.project, cfg=CFG, now=NOW)
    c = row.content
    assert (row.period_start, row.period_end) == (
        datetime(2026, 10, 2, 1, tzinfo=UTC),
        datetime(2026, 10, 3, 1, tzinfo=UTC),
    )
    assert c["totals"] == {
        "findings": 6,
        "alerts": 3,
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    assert {x["category"]: x["findings"] for x in c["by_category"]}["typosquat_domain"] == 2
    # 中级告警汇总：包括更早尚未汇报的；High 已即时推送，不在其中
    assert [a["alert_id"] for a in c["alerts"]] == [ids["old"][1], ids["medium"][1], ids["vuln"][1]]
    assert c["alerts"][2]["subject"] == "CVE-2026-12345 EdgeGate VPN Bypass"
    assert [n["finding_id"] for n in c["news"]] == [ids["news"][0]]  # 模型判为「不是」的被排除
    assert c["news"][0]["summary"] == "批准贷款" and c["news"][0]["url"] == "https://news.example/a"
    assert c["vulnerabilities"][0]["software"] == ["Example Networks EdgeGate VPN"]
    assert c["vulnerabilities"][0]["alert_id"] == ids["vuln"][1]
    alerts = (await session.scalars(select(Alert).where(Alert.severity == "medium"))).all()
    assert all(a.digest_sent_at == NOW for a in alerts)


async def test_generate_is_idempotent(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _world(session, sbr_rules)
    first = await reports.generate(session, "daily", project=sbr_rules.project, cfg=CFG, now=NOW)
    again = await reports.generate(
        session, "daily", project=sbr_rules.project, cfg=CFG, now=NOW + timedelta(minutes=20)
    )
    assert again.id == first.id and len((await session.scalars(select(Report))).all()) == 1
    later = await reports.generate(
        session, "daily", project=sbr_rules.project, cfg=CFG, now=NOW + timedelta(hours=1)
    )
    assert later.id != first.id and later.content["alerts"] == []  # 已汇报的告警不再重复收入


async def test_acknowledged_medium_alert_still_enters_daily_report(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ids = await _world(session, sbr_rules)
    alert = await session.get(Alert, ids["medium"][1])
    assert alert is not None
    alert.status = "acknowledged"
    await session.flush()
    row = await reports.generate(session, "daily", project=sbr_rules.project, cfg=CFG, now=NOW)
    assert ids["medium"][1] in [item["alert_id"] for item in row.content["alerts"]]


async def test_weekly_report(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    ids = await _world(session, sbr_rules)
    row = await reports.generate(session, "weekly", project=sbr_rules.project, cfg=CFG, now=NOW)
    c = row.content
    assert c["totals"]["findings"] == 7 and c["totals"]["alerts"] == 4
    assert c["alerts"][0]["alert_id"] == ids["high"][1]  # 按严重级别排序
    assert c["alerts"][0]["subject"] == "https://sbr-loans.com/login"
    assert c["low"]["count"] == 3 and c["low"]["top"][0]["score"] == 25
    assert c["triage"] == {} and c["takedowns"] == {"opened": 0, "resolved": 0}
    medium = await session.get(Alert, ids["medium"][1])
    assert medium is not None and medium.digest_sent_at is None  # 周报不影响日报汇总


async def _takedown(
    session: AsyncSession, project: str, alert_id: int, finding_id: int, state: str
) -> None:
    user = await security.create_user(session, username="responder", password="correct horse battery staple",
                                      roles=["responder"], now=NOW)  # fmt: skip
    session.add(Takedown(project_id=project, alert_id=alert_id, finding_id=finding_id, domain="sbr-old.top",
                         target={}, language="zh-CN", subject="s", body="b", state=state, created_by=user.id,
                         created_at=NOW, updated_at=NOW))  # fmt: skip
    await session.flush()


async def test_monthly_report(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    def at(month: int, day: int) -> datetime:
        return datetime(2026, month, day, 12, tzinfo=UTC)

    async def seed(value: str, category: str, score: int, when: datetime, *, alert: bool = True,
                   etype: str = "domain", match: dict[str, Any] | None = None) -> tuple[int, int | None]:  # fmt: skip
        return await _seed(
            session, sbr_rules, etype, value, category, score, match or {}, when=when, alert=alert
        )

    await seed("sbr-august.top", "phishing_site", 70, at(8, 15))
    critical = await seed("https://sbr-pay.top/login", "phishing_site", 90, at(9, 10), etype="url",
                          match={"url": "https://sbr-pay.top/login"})  # fmt: skip
    high = await seed("sbr-old.top", "typosquat_domain", 70, at(9, 5))
    await seed("sbr-portal.top", "typosquat_domain", 50, at(9, 20))
    await seed(
        "sbr-october.top", "typosquat_domain", 75, datetime(2026, 10, 2, tzinfo=UTC)
    )  # 不在本期
    mention = await seed("cluster:1", "negative_press", 30, at(9, 12), alert=False, etype="document",
                         match={**DOC, "llm": {"verdict": "yes", "summary": "负面报道"}})  # fmt: skip
    # 模型判为「不是本机构」
    await seed("cluster:2", "fraud_scam", 35, at(9, 13), alert=False, etype="document",
               match={**DOC, "llm": {"verdict": "no"}})  # fmt: skip
    await seed(
        "cluster:3", "brand_mention", 25, at(9, 14), alert=False, etype="document", match=DOC
    )
    kev = {"kev": {"cve": "CVE-2026-12345", "name": "EdgeGate VPN Bypass"},
           "software": [{"vendor": "Example Networks", "products": ["EdgeGate VPN"]}]}  # fmt: skip
    vuln = await seed("CVE-2026-12345", "vulnerability", 55, at(9, 3), etype="cve", match=kev)
    await seed("sbr-low.top", "typosquat_domain", 25, at(9, 21), alert=False)
    closed = await session.get(Alert, high[1])
    assert closed is not None
    closed.status, closed.triage_verdict = "closed", "true_positive"
    await _takedown(session, sbr_rules.project, closed.id, high[0], "submitted")

    row = await reports.generate(session, "monthly", project=sbr_rules.project, cfg=CFG, now=NOW)
    c = row.content
    assert (row.period_start, row.period_end) == (
        datetime(2026, 9, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )
    assert c["totals"] == {
        "findings": 8,
        "alerts": 4,
        "critical": 1,
        "high": 1,
        "medium": 2,
        "low": 4,
    }
    assert c["previous"] == {
        "findings": 1,
        "alerts": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
    }
    assert c["by_category"] == [
        {"category": "typosquat_domain", "alerts": 2, "previous": 0},
        {"category": "phishing_site", "alerts": 1, "previous": 1},
        {"category": "vulnerability", "alerts": 1, "previous": 0},
    ]
    # 重点事件只收严重与高级，按严重级别排序，带当前状态、研判结论与最近一次下架的状态
    assert [(a["alert_id"], a["status"], a["verdict"], a["takedown"]) for a in c["alerts"]] == [
        (critical[1], "open", None, None),
        (high[1], "closed", "true_positive", "submitted"),
    ]
    assert c["alerts"][0]["subject"] == "https://sbr-pay.top/login"
    assert [n["finding_id"] for n in c["news"]] == [
        mention[0]
    ]  # 只收负面舆情与冒名诈骗，排除模型判为「不是」的
    assert [v["finding_id"] for v in c["vulnerabilities"]] == [vuln[0]]
    assert c["counts"] == {"news": 1, "vulnerabilities": 1}
    assert [m["month"] for m in c["trend"]] == [
        "2026-04",
        "2026-05",
        "2026-06",
        "2026-07",
        "2026-08",
        "2026-09",
    ]
    assert c["trend"][-2:] == [
        {"month": "2026-08", "critical": 0, "high": 1, "medium": 0},
        {"month": "2026-09", "critical": 1, "high": 1, "medium": 2},
    ]
    medium = (await session.scalars(select(Alert).where(Alert.severity == "medium"))).all()
    assert all(a.digest_sent_at is None for a in medium)  # 月报不影响日报汇总


async def test_monthly_report_named_month_is_idempotent(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _seed(session, sbr_rules, "domain", "sbr-august.top", "phishing_site", 70, {},
                when=datetime(2026, 8, 15, tzinfo=UTC), alert=True)  # fmt: skip
    first = await reports.generate(
        session, "monthly", project=sbr_rules.project, cfg=CFG, now=NOW, month="2026-08"
    )
    assert first.content["totals"]["alerts"] == 1 and first.content["previous"]["alerts"] == 0
    again = await reports.generate(
        session, "monthly", project=sbr_rules.project, cfg=CFG, now=NOW, month="2026-08"
    )
    assert again.id == first.id
    with pytest.raises(ValueError):
        await reports.generate(
            session, "monthly", project=sbr_rules.project, cfg=CFG, now=NOW, month="2026-10"
        )
