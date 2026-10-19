from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Alert, Finding, FindingObservation, WatchedDomain
from opti.pipeline import watchlist as wl
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem
from opti.sdk.testing import make_context, static_enricher

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
PROJECT = "sample-brand-protection"
PARKED = {"reachable": True, "status": 200, "title": "sbr-loans.com is for sale",
          "has_password_field": False, "brand_terms": []}  # fmt: skip
PHISH = {"reachable": True, "status": 200, "title": "Sample Brand Login",
         "has_password_field": True, "brand_terms": ["Sample Brand"]}  # fmt: skip


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def _processor(rules: ProjectRules, http_state: dict[str, Any], clock: Clock) -> Processor:
    ctx = make_context(rules)
    enrichers = {
        "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "mx": []}),
        "rdap": static_enricher(ctx, "rdap", {"registration": "2026-09-30T00:00:00Z"}, ttl=86400),
        "tranco": static_enricher(ctx, "tranco", {"rank": None}, ttl=86400),
        "http_probe": static_enricher(ctx, "http_probe", lambda _v: dict(http_state)),
    }
    return Processor(rules, EnrichmentService(enrichers, clock=clock), clock=clock)


def _item(domain: str, *, connector: str = "certstream", source: str = "p1",
          project: str = PROJECT, **extra: Any) -> RawItem:  # fmt: skip
    payload = {"matches": [{"domain": domain}], **extra}
    return RawItem(connector, source, NOW, None, payload, project_ids=(project,))


async def _count(session: AsyncSession, model: type) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


async def test_new_lookalike_creates_finding_alert_and_watch(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p = _processor(sbr_rules, dict(PARKED), Clock())
    r = await p.process(session, _item("sbr-loans.com"))
    assert (
        r.stored and len(r.findings) == 1 and len(r.alerts) == 1 and r.watched == ["sbr-loans.com"]
    )
    f = await session.get(Finding, r.findings[0])
    assert (
        f is not None
        and f.severity == "medium"
        and f.category == "typosquat_domain"
        and f.score == 48
    )


async def test_reprocessing_is_idempotent(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    p = _processor(sbr_rules, dict(PARKED), Clock())
    await p.process(session, _item("sbr-loans.com"))
    r = await p.process(session, _item("sbr-loans.com"))
    assert not r.stored and r.alerts == [] and r.watched == []
    assert await _count(session, Finding) == 1
    assert await _count(session, Alert) == 1
    assert await _count(session, FindingObservation) == 1


async def test_replay_after_ttl_does_not_rescore(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    http_state, clock = dict(PARKED), Clock()
    p = _processor(sbr_rules, http_state, clock)
    first = await p.process(session, _item("sbr-loans.com"))
    http_state.update(PHISH)
    clock.now = NOW + timedelta(hours=2)
    r = await p.process(session, _item("sbr-loans.com"))
    assert not r.stored and r.alerts == []
    f = await session.get(Finding, first.findings[0])
    assert f is not None and f.severity == "medium"
    assert await _count(session, Alert) == 1


async def test_escalation_after_cache_expiry(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    http_state, clock = dict(PARKED), Clock()
    p = _processor(sbr_rules, http_state, clock)
    first = await p.process(session, _item("sbr-loans.com"))
    http_state.update(PHISH)
    clock.now = NOW + timedelta(hours=2)
    r = await p.process(session, _item("sbr-loans.com", connector="crtsh", source="1001"))
    assert len(r.alerts) == 1
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.severity == "critical" and f.category == "phishing_site"
    old = await session.get(Alert, first.alerts[0])
    assert old is not None
    await session.refresh(old)
    assert old.status == "superseded"


@pytest.mark.parametrize("domain", ["crossbrace.com", "sbrbank.com", "sbr.int"])
async def test_non_findings_are_ignored(
    session: AsyncSession, sbr_rules: ProjectRules, domain: str
) -> None:
    r = await _processor(sbr_rules, dict(PARKED), Clock()).process(session, _item(domain))
    assert r.stored and r.findings == []


async def test_other_project_is_ignored(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    r = await _processor(sbr_rules, dict(PARKED), Clock()).process(
        session, _item("sbr-loans.com", project="other")
    )
    assert r.stored and r.findings == []


async def test_own_domain_unapproved_certificate(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p = _processor(sbr_rules, dict(PARKED), Clock())
    r = await p.process(
        session,
        _item(
            "mail.sbr.int",
            connector="own_domain_ct",
            issuer_approved=False,
            cert={"issuer_o": "Evil CA"},
        ),
    )
    assert len(r.findings) == 1 and len(r.alerts) == 1
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.category == "unapproved_certificate" and f.severity == "high"
    r2 = await p.process(
        session, _item("www.sbr.int", connector="own_domain_ct", source="o2", issuer_approved=None)
    )
    assert r2.findings == []


async def test_on_watch_change_rescores(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    http_state, clock = dict(PARKED), Clock()
    p = _processor(sbr_rules, http_state, clock)
    await p.process(session, _item("sbr-loans.com"))
    wd = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "sbr-loans.com"))
    assert wd is not None
    http_state.update(PHISH)
    clock.now = NOW + timedelta(hours=4)
    await wl.recheck(
        session, wd, enrichment=p.enrichment, on_change=p.on_watch_change, now=clock.now
    )
    f = await session.scalar(select(Finding))
    assert f is not None and f.severity == "critical"
    assert "watchlist" in f.sources
    assert await _count(session, Alert) == 2
