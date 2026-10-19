from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.config import AlertingConfig, Channel
from opti.alerting.dispatcher import AlertDispatcher, Route
from opti.alerting.views import AlertView, Notice
from opti.core.config import ProjectRules
from opti.core.reports import ReportView, empty_content
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, Report

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 12, 8, 0, tzinfo=UTC)


class Sink:
    def __init__(self, name: str, fail: bool = False) -> None:
        self.name, self.fail = name, fail
        self.alerts: list[int] = []
        self.reports: list[int] = []
        self.notices = 0

    async def send_alert(self, view: AlertView) -> None:
        if self.fail:
            raise RuntimeError("down")
        self.alerts.append(view.alert_id)

    async def send_report(self, report: ReportView) -> None:
        self.reports.append(report.report_id)

    async def send_notice(self, notice: Notice) -> None:
        self.notices += 1


def _ch(
    cid: str,
    severities=("critical", "high"),
    categories=(),
    reports=(),
    notices=False,
    enabled=True,
) -> Channel:  # type: ignore[no-untyped-def]
    return Channel.model_validate({"id": cid, "name": cid, "type": "teams", "enabled": enabled,
                                   "severities": list(severities), "categories": list(categories),
                                   "reports": list(reports), "notices": notices})  # fmt: skip


async def _alert(
    s: AsyncSession,
    rules: ProjectRules,
    domain: str,
    sev: Severity,
    cat: Category,
    at: datetime = NOW,
) -> int:
    await repo.upsert_project(s, rules)
    e = await repo.upsert_entity(s, "domain", domain, at)
    up = await repo.upsert_finding(
        s, project_id=rules.project, entity=e, score=Score(80, sev, cat, {}),
        match={"reasons": [{"reason": "brand_label"}]}, source="certstream", now=at,
    )  # fmt: skip
    return (await repo.open_alert(s, up.finding, sev, at)).id


def _dispatcher(*routes: Route) -> AlertDispatcher:
    return AlertDispatcher(
        AlertingConfig(public_base_url="https://ti.example"), list(routes), clock=lambda: NOW
    )


async def test_routes_by_severity_and_category(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    phish = await _alert(session, sbr_rules, "sbr-login.top", Severity.HIGH, Category.PHISHING_SITE)
    press = await _alert(session, sbr_rules, "sbr-news.top", Severity.HIGH, Category.NEGATIVE_PRESS)
    medium = await _alert(
        session, sbr_rules, "sbr-mid.top", Severity.MEDIUM, Category.PHISHING_SITE
    )
    secops, brand = Sink("secops"), Sink("brand")
    d = _dispatcher(
        Route(_ch("secops"), secops), Route(_ch("brand", categories=["negative_press"]), brand)
    )
    assert await d.dispatch_pending(session) == 2
    assert sorted(secops.alerts) == sorted([phish, press]) and brand.alerts == [press]
    row = await session.get(Alert, medium)
    assert row is not None and row.notified_at is None  # 没有渠道接收中危：不选取


async def test_no_matching_channel_marks_done(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    aid = await _alert(session, sbr_rules, "sbr-x.top", Severity.HIGH, Category.PHISHING_SITE)
    d = _dispatcher(Route(_ch("brand", categories=["negative_press"]), Sink("brand")))
    assert await d.dispatch_pending(session) == 0
    row = await session.get(Alert, aid)
    assert row is not None and row.notified_at == NOW and row.notified_sinks == []


async def test_unavailable_target_keeps_alert_pending(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    aid = await _alert(session, sbr_rules, "sbr-x.top", Severity.HIGH, Category.PHISHING_SITE)
    ok = Sink("ok")
    d = _dispatcher(Route(_ch("ok"), ok), Route(_ch("broken"), None, "未设置 Webhook 地址"))
    assert await d.dispatch_pending(session) == 0
    row = await session.get(Alert, aid)
    assert row is not None and row.notified_at is None and row.notified_sinks == ["ok"]
    fixed = Sink("broken")
    d = _dispatcher(Route(_ch("ok"), ok), Route(_ch("broken"), fixed))
    assert await d.dispatch_pending(session) == 1
    assert ok.alerts == [aid] and fixed.alerts == [aid]


async def test_removed_channel_no_longer_blocks(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    aid = await _alert(session, sbr_rules, "sbr-x.top", Severity.HIGH, Category.PHISHING_SITE)
    d = _dispatcher(Route(_ch("a"), Sink("a")), Route(_ch("b"), Sink("b", fail=True)))
    await d.dispatch_pending(session)
    d = _dispatcher(Route(_ch("a"), Sink("a")))
    assert await d.dispatch_pending(session) == 1
    row = await session.get(Alert, aid)
    assert row is not None and row.notified_at == NOW


async def test_old_alerts_are_not_selected(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _alert(
        session,
        sbr_rules,
        "sbr-old.top",
        Severity.HIGH,
        Category.PHISHING_SITE,
        at=NOW - timedelta(days=8),
    )
    sink = Sink("a")
    assert await _dispatcher(Route(_ch("a"), sink)).dispatch_pending(session) == 0
    assert sink.alerts == []


async def test_legacy_ids_keep_delivery_history(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    aid = await _alert(session, sbr_rules, "sbr-x.top", Severity.HIGH, Category.PHISHING_SITE)
    row = await session.get(Alert, aid)
    assert row is not None
    row.notified_sinks = ["teams"]
    await session.flush()
    cfg = AlertingConfig.model_validate({"immediate": ["high"], "teams": {"enabled": True},
                                         "email": {"enabled": True, "recipients": ["soc@example.org"]}})  # fmt: skip
    teams, email = Sink("teams"), Sink("email")
    sinks = {"teams": teams, "email": email}
    d = AlertDispatcher(cfg, [Route(c, sinks[c.id]) for c in cfg.channels], clock=lambda: NOW)
    assert await d.dispatch_pending(session) == 1
    assert teams.alerts == [] and email.alerts == [aid]


async def test_reports_and_notices_follow_channel_settings(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    start = NOW - timedelta(days=7)
    weekly = Report(project_id=sbr_rules.project, kind="weekly", period_start=start, period_end=NOW,
                    created_at=NOW, content=empty_content("weekly", start=start, end=NOW), sent_sinks=[])  # fmt: skip
    daily = Report(project_id=sbr_rules.project, kind="daily", period_start=start, period_end=NOW,
                   created_at=NOW, content=empty_content("daily", start=start, end=NOW), sent_sinks=[])  # fmt: skip
    session.add_all([weekly, daily])
    await session.flush()
    mgmt, ops = Sink("mgmt"), Sink("ops")
    d = _dispatcher(
        Route(_ch("mgmt", severities=(), reports=["weekly"]), mgmt),
        Route(_ch("ops", reports=[], notices=True), ops),
    )
    assert await d.send_reports(session) == 2  # 日报没有目标渠道：直接记已发送
    assert mgmt.reports == [weekly.id] and ops.reports == []
    notice = Notice(title="t", facts=(), link="https://ti.example")
    assert await d.send_notice(notice) is True and ops.notices == 1 and mgmt.notices == 0
    assert (
        await _dispatcher(Route(_ch("x"), Sink("x"))).send_notice(notice) is True
    )  # 无人接收：视为送达
    assert (
        await _dispatcher(Route(_ch("y", notices=True), None, "down")).send_notice(notice) is False
    )
