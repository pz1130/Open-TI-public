from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity, severity_for
from opti.core.siem import SiemEvent
from opti.db import repo
from opti.db.models import Alert
from opti.pipeline import siem
from opti.sharing import SiemSettings

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, tzinfo=UTC)
BASE = "https://ti.example"


class FakeSender:
    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name, self.fail = name, fail
        self.sent: list[SiemEvent] = []

    async def send(self, events: Sequence[SiemEvent]) -> list[int]:
        if self.fail:
            raise ConnectionRefusedError("siem down")
        self.sent += events
        return [e.alert_id for e in events]


async def _alert(session: AsyncSession, rules: ProjectRules, etype: str, value: str, category: str, score: int,
                 *, when: datetime = NOW - timedelta(minutes=5)) -> int:  # fmt: skip
    await repo.upsert_project(session, rules)
    entity = await repo.upsert_entity(session, etype, value, when)
    s = Score(score, severity_for(score), Category(category), {"base": score})
    up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=s,
                                   match={"reasons": [{"reason": "brand_label"}]}, source="test", now=when)  # fmt: skip
    return (await repo.open_alert(session, up.finding, s.severity, when)).id


async def test_push_tracks_each_sink(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    high = await _alert(
        session, sbr_rules, "url", "https://sbr-loans.com/login", "phishing_site", 80
    )
    medium = await _alert(session, sbr_rules, "domain", "sbr-portal.top", "typosquat_domain", 50)
    await _alert(session, sbr_rules, "domain", "sbr-low.top", "typosquat_domain", 30)  # 低于 medium
    await _alert(
        session,
        sbr_rules,
        "domain",
        "sbr-old.top",
        "typosquat_domain",
        80,
        when=NOW - timedelta(days=8),
    )
    good, bad = FakeSender("syslog"), FakeSender("webhook", fail=True)
    cfg = SiemSettings()
    assert await siem.push_pending(session, [good, bad], cfg=cfg, base_url=BASE, now=NOW) == 0
    assert sorted(e.alert_id for e in good.sent) == [high, medium]
    a = await session.get(Alert, high)
    assert a is not None and a.siem_sinks == ["syslog"] and a.siem_sent_at is None
    bad.fail = False
    assert await siem.push_pending(session, [good, bad], cfg=cfg, base_url=BASE, now=NOW) == 2
    assert len(good.sent) == 2 and len(bad.sent) == 2  # 已送达的渠道不重发
    a = await session.get(Alert, high)
    assert a is not None and a.siem_sent_at == NOW and sorted(a.siem_sinks) == ["syslog", "webhook"]
    event = next(e for e in bad.sent if e.alert_id == high)
    assert event.title == "https://sbr-loans.com/login" and event.link == f"{BASE}/alerts/{high}"
    assert event.observables() == {"url": "https://sbr-loans.com/login", "domain": "sbr-loans.com"}
    assert await siem.push_pending(session, [good, bad], cfg=cfg, base_url=BASE, now=NOW) == 0


async def test_filters(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    phish = await _alert(
        session, sbr_rules, "url", "https://sbr-loans.com/login", "phishing_site", 80
    )
    await _alert(session, sbr_rules, "domain", "sbr-portal.top", "typosquat_domain", 70)
    sender = FakeSender("syslog")
    only_phishing = SiemSettings(categories=("phishing_site",))
    assert (
        await siem.push_pending(session, [sender], cfg=only_phishing, base_url=BASE, now=NOW) == 1
    )
    assert [e.alert_id for e in sender.sent] == [phish]
    assert await siem.push_pending(session, [], cfg=SiemSettings(), base_url=BASE, now=NOW) == 0
    high_only = SiemSettings(min_severity=Severity.CRITICAL)
    assert (
        await siem.push_pending(session, [FakeSender("x")], cfg=high_only, base_url=BASE, now=NOW)
        == 0
    )


async def test_ignored_and_revoked_certificate_alerts_are_not_pushed(
    session: AsyncSession,
    sbr_rules: ProjectRules,
) -> None:
    ignored = await _alert(session, sbr_rules, "domain", "sbr-portal.top", "typosquat_domain", 70)
    cert = await _alert(
        session, sbr_rules, "tls_endpoint", "example.com@1", "certificate_expiry", 70
    )
    alert = await session.get(Alert, ignored)
    assert alert is not None
    alert.ignored_at = NOW
    certificate = await session.get(Alert, cert)
    assert certificate is not None
    certificate.status = "closed"
    await session.flush()
    sender = FakeSender("webhook")
    assert (
        await siem.push_pending(session, [sender], cfg=SiemSettings(), base_url=BASE, now=NOW) == 0
    )
    assert sender.sent == []
    alert.ignored_at = None
    await session.flush()
    assert (
        await siem.push_pending(session, [sender], cfg=SiemSettings(), base_url=BASE, now=NOW) == 1
    )
    assert [e.alert_id for e in sender.sent] == [ignored]
