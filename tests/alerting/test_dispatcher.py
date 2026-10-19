import smtplib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.config import AlertingConfig
from opti.alerting.dispatcher import AlertDispatcher, Route
from opti.alerting.views import AlertView, Notice, load_views
from opti.core.config import ProjectRules
from opti.core.reports import ReportView, empty_content
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, Report
from opti.sdk.http import HttpError

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


class FakeSink:
    def __init__(self, fail: bool = False, name: str = "fake") -> None:
        self.name = name
        self.fail = fail
        self.alerts: list[AlertView] = []
        self.reports: list[ReportView] = []
        self.attempts = 0

    async def send_alert(self, view: AlertView) -> None:
        self.attempts += 1
        if self.fail:
            raise RuntimeError("webhook down")
        self.alerts.append(view)

    async def send_notice(self, notice: Notice) -> None:
        self.attempts += 1
        if self.fail:
            raise RuntimeError("webhook down")

    async def send_report(self, report: ReportView) -> None:
        self.attempts += 1
        if self.fail:
            raise RuntimeError("smtp refused")
        self.reports.append(report)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, minutes: float) -> None:
        self.now += timedelta(minutes=minutes)


async def _alert(
    session: AsyncSession, rules: ProjectRules, domain: str, severity: Severity
) -> int:
    await repo.upsert_project(session, rules)
    e = await repo.upsert_entity(session, "domain", domain, NOW)
    score = Score(90 if severity == Severity.HIGH else 50, severity, Category.TYPOSQUAT_DOMAIN, {})
    up = await repo.upsert_finding(
        session, project_id=rules.project, entity=e, score=score,
        match={"reasons": [{"reason": "brand_label"}]}, source="certstream", now=NOW,
    )  # fmt: skip
    return (await repo.open_alert(session, up.finding, severity, NOW)).id


async def test_only_active_project_alerts_are_dispatched(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    other = sbr_rules.model_copy(update={"project": "other"})
    active_id = await _alert(session, sbr_rules, "sbr-active.com", Severity.HIGH)
    inactive_id = await _alert(session, other, "sbr-inactive.com", Severity.HIGH)
    sink = FakeSink()
    dispatcher = AlertDispatcher(
        AlertingConfig(), [Route.default(sink)], clock=lambda: NOW, project_id=sbr_rules.project
    )
    assert await dispatcher.dispatch_pending(session) == 1
    assert [view.alert_id for view in sink.alerts] == [active_id]
    assert (await session.get(Alert, inactive_id)).notified_at is None


async def test_dispatch_pending_sends_immediate_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    await _alert(session, sbr_rules, "sbr-portal.top", Severity.MEDIUM)
    sink = FakeSink()
    d = AlertDispatcher(
        AlertingConfig(public_base_url="https://ti.example"),
        [Route.default(sink)],
        clock=lambda: NOW,
    )
    assert await d.dispatch_pending(session) == 1
    assert [v.alert_id for v in sink.alerts] == [high]
    assert sink.alerts[0].link == f"https://ti.example/alerts/{high}"
    assert sink.alerts[0].reasons == ("brand_label",)
    assert await d.dispatch_pending(session) == 0
    a = await session.get(Alert, high)
    assert a is not None and a.notified_at == NOW


async def test_failed_sink_keeps_alert_pending(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    d = AlertDispatcher(
        AlertingConfig(),
        [Route.default(FakeSink(name="a")), Route.default(FakeSink(fail=True, name="b"))],
        clock=lambda: NOW,
    )
    assert await d.dispatch_pending(session) == 0
    a = await session.get(Alert, high)
    assert a is not None and a.notified_at is None


async def test_retry_only_resends_to_failed_sink(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    """Teams 成功、邮件失败：重试只补发邮件，不能每 5 分钟往 Teams 重复推送。"""
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    teams, email = FakeSink(name="teams"), FakeSink(fail=True, name="email")
    clock = Clock()
    d = AlertDispatcher(AlertingConfig(), [Route.default(teams), Route.default(email)], clock=clock)
    assert await d.dispatch_pending(session) == 0
    assert await d.dispatch_pending(session) == 0
    assert [v.alert_id for v in teams.alerts] == [high]
    email.fail = False
    clock.advance(5)  # 等邮件渠道退避结束
    assert await d.dispatch_pending(session) == 1
    assert [v.alert_id for v in teams.alerts] == [high]
    assert [v.alert_id for v in email.alerts] == [high]
    a = await session.get(Alert, high)
    assert a is not None and a.notified_at == clock.now
    assert sorted(a.notified_sinks) == ["email", "teams"]


async def test_acknowledgement_does_not_cancel_failed_channel_retry(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    teams, email = FakeSink(name="teams"), FakeSink(fail=True, name="email")
    clock = Clock()
    dispatcher = AlertDispatcher(
        AlertingConfig(), [Route.default(teams), Route.default(email)], clock=clock
    )
    assert await dispatcher.dispatch_pending(session) == 0
    alert = await session.get(Alert, high)
    assert alert is not None
    alert.status = "acknowledged"
    await session.flush()
    email.fail = False
    clock.advance(5)
    assert await dispatcher.dispatch_pending(session) == 1
    assert [view.alert_id for view in teams.alerts] == [high]
    assert [view.alert_id for view in email.alerts] == [high]


async def _report(session: AsyncSession, rules: ProjectRules) -> int:
    await repo.upsert_project(session, rules)
    start = NOW - timedelta(days=1)
    row = Report(
        project_id=rules.project,
        kind="daily",
        period_start=start,
        period_end=NOW,
        created_at=NOW,
        content=empty_content("daily", start=start, end=NOW),
        sent_sinks=[],
    )
    session.add(row)
    await session.flush()
    return row.id


async def test_report_retry_only_resends_to_failed_sink(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    rid = await _report(session, sbr_rules)
    teams, email = FakeSink(name="teams"), FakeSink(fail=True, name="email")
    d = AlertDispatcher(
        AlertingConfig(public_base_url="https://ti.example"),
        [Route.default(teams), Route.default(email)],
        clock=(clock := Clock()),
    )
    assert await d.send_reports(session) == 0
    email.fail = False
    clock.advance(5)
    assert await d.send_reports(session) == 1
    assert [r.report_id for r in teams.reports] == [rid]
    assert [r.report_id for r in email.reports] == [rid]
    row = await session.get(Report, rid)
    assert row is not None and row.sent_at == clock.now
    assert sorted(row.sent_sinks) == ["email", "teams"]
    assert await d.send_reports(session) == 0


async def test_load_views_keeps_snapshot_after_finding_changes(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    entity = await repo.upsert_entity(session, "domain", "sbr-loans.com", NOW)
    score = Score(90, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {})
    up = await repo.upsert_finding(
        session, project_id=sbr_rules.project, entity=entity, score=score,
        match={"reasons": [{"reason": "fraud_affix"}, {"reason": "brand_label"}]},
        source="certstream", now=NOW,
    )  # fmt: skip
    alert_id = (await repo.open_alert(session, up.finding, Severity.HIGH, NOW)).id
    up.finding.score = 12
    up.finding.category = "phishing_site"
    up.finding.severity = "low"
    up.finding.match = {"reasons": [{"reason": "homoglyph"}]}
    entity.value = "changed.example"
    await session.flush()
    views = await load_views(session, [alert_id], "https://ti.example")
    assert len(views) == 1
    view = views[0]
    assert view.severity == "high"
    assert view.score == 90
    assert view.category == "typosquat_domain"
    assert view.domain == "sbr-loans.com"
    assert view.reasons == ("brand_label", "fraud_affix")


async def test_no_channels_marks_report_done_and_leaves_alerts_pending(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    rid = await _report(session, sbr_rules)
    d = AlertDispatcher(AlertingConfig(), [], clock=lambda: NOW)
    assert await d.dispatch_pending(session) == 0
    assert await d.send_reports(session) == 1
    alert, row = await session.get(Alert, high), await session.get(Report, rid)
    assert alert is not None and alert.notified_at is None
    assert row is not None and row.sent_at == NOW


async def test_failing_channel_is_tried_once_per_round(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    """渠道故障时，一轮里只等一次超时，其余告警跳过该渠道，健康渠道照常送达。"""
    ids = [await _alert(session, sbr_rules, f"sbr-loans{i}.com", Severity.HIGH) for i in range(3)]
    ok, down = FakeSink(name="ok"), FakeSink(fail=True, name="down")
    d = AlertDispatcher(AlertingConfig(), [Route.default(ok), Route.default(down)], clock=Clock())
    assert await d.dispatch_pending(session) == 0
    assert down.attempts == 1
    assert sorted(v.alert_id for v in ok.alerts) == sorted(ids)


async def test_failing_channel_backs_off_then_recovers(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    clock = Clock()
    down = FakeSink(fail=True, name="down")
    d = AlertDispatcher(AlertingConfig(), [Route.default(down)], clock=clock)
    await d.dispatch_pending(session)
    assert down.attempts == 1
    clock.advance(4)
    await d.dispatch_pending(session)
    assert down.attempts == 1  # 5 分钟内不重试
    clock.advance(1)
    await d.dispatch_pending(session)
    assert down.attempts == 2  # 再次失败，下一次等 10 分钟
    clock.advance(9)
    await d.dispatch_pending(session)
    assert down.attempts == 2
    clock.advance(1)
    down.fail = False
    assert await d.dispatch_pending(session) == 1
    assert [v.alert_id for v in down.alerts] == [high]
    # 成功一次即复位：之后再失败，又从 5 分钟开始
    await _alert(session, sbr_rules, "sbr-portal.com", Severity.HIGH)
    down.fail = True
    await d.dispatch_pending(session)
    attempts = down.attempts
    clock.advance(5)
    await d.dispatch_pending(session)
    assert down.attempts == attempts + 1


async def test_backoff_is_capped_at_thirty_minutes(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    clock = Clock()
    down = FakeSink(fail=True, name="down")
    d = AlertDispatcher(AlertingConfig(), [Route.default(down)], clock=clock)
    await d.dispatch_pending(session)
    for wait in (5, 10, 20, 30, 30):
        clock.advance(wait)
        before = down.attempts
        await d.dispatch_pending(session)
        assert down.attempts == before + 1, wait


async def test_notice_skips_channel_in_backoff(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    clock = Clock()
    down = FakeSink(fail=True, name="down")
    d = AlertDispatcher(AlertingConfig(), [Route.default(down)], clock=clock)
    await d.dispatch_pending(session)
    assert await d.send_notice(Notice(title="t", facts=(), link="")) is False
    assert down.attempts == 1


class PoisonSink(FakeSink):
    """只有某一条告警被服务器明确拒收，其余正常。"""

    def __init__(self, poison: int, error: Exception) -> None:
        super().__init__(name="poison")
        self.poison = poison
        self.error = error

    async def send_alert(self, view: AlertView) -> None:
        self.attempts += 1
        if view.alert_id == self.poison:
            raise self.error
        self.alerts.append(view)


@pytest.mark.parametrize(
    "error",
    [
        HttpError("https://hook.example", 400, "bad card"),
        smtplib.SMTPDataError(552, b"message too large"),
    ],
)
async def test_rejected_message_does_not_back_off_channel(
    session: AsyncSession, sbr_rules: ProjectRules, error: Exception
) -> None:
    """服务器明确拒收某一条（最早的）告警时，不能让整个渠道退避、堵住后面的告警。"""
    bad = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    good = await _alert(session, sbr_rules, "sbr-portal.com", Severity.HIGH)
    sink = PoisonSink(bad, error)
    d = AlertDispatcher(AlertingConfig(), [Route.default(sink)], clock=Clock())
    assert await d.dispatch_pending(session) == 1
    later = await _alert(session, sbr_rules, "sbr-online.com", Severity.HIGH)
    assert await d.dispatch_pending(session) == 1
    assert [v.alert_id for v in sink.alerts] == [good, later]


@pytest.mark.parametrize(
    "error",
    [
        HttpError("https://hook.example", 503, "unavailable"),
        HttpError("https://hook.example", 429, "throttled"),
        HttpError("https://hook.example", None, "timeout"),
        smtplib.SMTPServerDisconnected("gone"),
        smtplib.SMTPResponseException(421, b"try later"),
    ],
)
async def test_channel_failure_backs_off(
    session: AsyncSession, sbr_rules: ProjectRules, error: Exception
) -> None:
    first = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    await _alert(session, sbr_rules, "sbr-portal.com", Severity.HIGH)
    sink = PoisonSink(first, error)
    d = AlertDispatcher(AlertingConfig(), [Route.default(sink)], clock=Clock())
    assert await d.dispatch_pending(session) == 0
    assert sink.attempts == 1


async def test_ignored_alert_waits_until_restored(
    session: AsyncSession,
    sbr_rules: ProjectRules,
) -> None:
    high = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    alert = await session.get(Alert, high)
    assert alert is not None
    alert.ignored_at = NOW
    await session.flush()
    sink = FakeSink()
    dispatcher = AlertDispatcher(AlertingConfig(), [Route.default(sink)], clock=lambda: NOW)
    assert await dispatcher.dispatch_pending(session) == 0 and sink.alerts == []
    assert alert.notified_at is None
    alert.ignored_at = None
    await session.flush()
    assert await dispatcher.dispatch_pending(session) == 1
    assert [a.alert_id for a in sink.alerts] == [high]
