from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Alert, Entity, Finding, WatchedDomain
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem
from opti.sdk.testing import make_context, static_enricher

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
PROJECT = "sample-brand-protection"
LOGIN = {"reachable": True, "status": 200, "has_password_field": True, "brand_terms": []}


def _processor(rules: ProjectRules) -> Processor:
    ctx = make_context(rules)
    enrichers = {
        "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "mx": []}),
        "rdap": static_enricher(ctx, "rdap", {"registration": "2026-09-30T00:00:00Z"}),
        "tranco": static_enricher(ctx, "tranco", {"rank": None}),
        "http_probe": static_enricher(ctx, "http_probe", dict(LOGIN), types=("domain", "url")),
    }
    return Processor(rules, EnrichmentService(enrichers, clock=lambda: NOW), clock=lambda: NOW)


def _item(indicators: list[dict[str, Any]], signal: str, *, source: str = "report_mailbox",
          sid: str = "m1", confirmed: bool = False, context: dict[str, Any] | None = None) -> RawItem:  # fmt: skip
    payload = {"indicators": indicators, "signal": signal,
               "intel": {"source": source, "confirmed": confirmed}, "context": context or {"subject": "Invoice"}}  # fmt: skip
    return RawItem(source, sid, NOW, None, payload, project_ids=(PROJECT,))


async def _one(session: AsyncSession, model: type) -> Any:
    return (await session.scalars(select(model))).one()


async def test_reported_unbranded_url(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    r = await _processor(sbr_rules).process(
        session, _item([{"type": "url", "value": "https://login-portal.top/x"}], "reported")
    )
    assert len(r.findings) == 1 and len(r.alerts) == 1
    f = await _one(session, Finding)
    assert f.category == "reported_phishing" and f.score == 75  # 45 + 15 + 登录框 15
    assert f.match["signal"] == "reported" and f.match["context"] == {"subject": "Invoice"}
    assert f.match["reasons"] == [{"reason": "reported"}]
    e = await session.get(Entity, f.entity_id)
    assert e is not None and (e.type, e.value) == ("url", "https://login-portal.top/x")


async def test_reported_branded_domain_joins_existing_flow(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    r = await _processor(sbr_rules).process(
        session, _item([{"type": "domain", "value": "sbr-loans.com"}], "reported")
    )
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.score_breakdown["owned_signal"] == 15
    assert f.match["status"] == "match" and f.match["signal"] == "reported"


async def test_canary_clone_site_is_watched(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    item = _item(
        [{"type": "domain", "value": "secure-online-banking.top"}],
        "canary",
        source="canary",
        confirmed=True,
    )
    r = await _processor(sbr_rules).process(session, item)
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.category == "clone_site" and f.severity in ("high", "critical")
    w = await _one(session, WatchedDomain)
    assert w.domain == "secure-online-banking.top"


async def test_dmarc_ip_volume_without_enrichment(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    item = _item(
        [{"type": "ip", "value": "45.33.32.156", "volume": 140}], "dmarc_fail", source="dmarc"
    )
    r = await _processor(sbr_rules).process(session, item)
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.category == "email_spoofing" and f.score == 40 + 15 + 20
    e = await session.get(Entity, f.entity_id)
    assert e is not None and e.type == "ip" and e.enrichment == {}


async def test_official_lookalike_and_invalid_are_skipped(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    inds = [{"type": "url", "value": "https://sbr.int/x"}, {"type": "domain", "value": "sbrbank.com"},
            {"type": "url", "value": "javascript:alert(1)"}, {"type": "ip", "value": "not-an-ip"},
            {"type": "ip", "value": "10.0.0.1"}]  # fmt: skip
    r = await _processor(sbr_rules).process(session, _item(inds, "reported"))
    assert r.findings == []
    assert await session.scalar(select(func.count()).select_from(Finding)) == 0


async def test_report_entity_and_indicator_cap(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    inds = [{"type": "report", "value": "r-1"}] + [
        {"type": "url", "value": f"https://spam{i}.top/a"} for i in range(80)
    ]
    r = await _processor(sbr_rules).process(
        session, _item(inds, "reported", source="public_report")
    )
    assert len(r.findings) == 50  # 每条最多 50 个指标
    report = (await session.scalars(select(Entity).where(Entity.type == "report"))).one()
    assert report.value == "r-1"


async def test_replay_does_not_duplicate(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    p = _processor(sbr_rules)
    item = _item([{"type": "url", "value": "https://login-portal.top/x"}], "reported")
    await p.process(session, item)
    await p.process(session, item)
    assert await session.scalar(select(func.count()).select_from(Alert)) == 1


async def test_report_contact_only_in_report_finding(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    from opti.db.models import RawItemRow

    item = _item(
        [
            {"type": "report", "value": "r-contact"},
            {"type": "url", "value": "https://login-portal.top/x"},
        ],
        "reported",
        source="public_report",
        context={"description": "report", "contact": "tel:private"},
    )
    result = await _processor(sbr_rules).process(session, item)
    assert len(result.findings) == 2
    for finding in (await session.scalars(select(Finding))).all():
        entity = await session.get(Entity, finding.entity_id)
        assert entity is not None
        if entity.type == "report":
            assert finding.match["context"]["contact"] == "tel:private"
        else:
            assert "contact" not in finding.match["context"]
    raw = (await session.scalars(select(RawItemRow))).one()
    assert raw.payload["context"]["contact"] is None


async def test_brand_feed_and_owned_signal_merge_without_reset(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    feed = RawItem(
        "openphish",
        "feed1",
        NOW,
        None,
        {"feed_url": "https://sbr-loans.com/pay", "intel": {"confirmed": True}},
        project_ids=(PROJECT,),
    )
    await processor.process(session, feed)
    report = _item(
        [
            {"type": "url", "value": "https://sbr-loans.com/pay"},
            {"type": "domain", "value": "sbr-loans.com"},
        ],
        "reported",
    )
    result = await processor.process(session, report)
    assert len(result.findings) == 1  # canonical host + original sender domain
    finding = await _one(session, Finding)
    assert finding.category == "phishing_site" and finding.score_breakdown["intel_hits"] == 20
    assert finding.score_breakdown["owned_signal"] == 15
    await processor.process(
        session, RawItem("openphish", "feed2", NOW, None, feed.payload, project_ids=(PROJECT,))
    )
    assert finding.match["signal"] == "reported" and finding.score_breakdown["owned_signal"] == 15
    assert set(finding.sources) == {"openphish", "report_mailbox"}


async def test_clone_watch_change_keeps_unbranded_signal(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    await processor.process(
        session,
        _item(
            [{"type": "domain", "value": "clone-portal.top"}],
            "canary",
            source="canary",
            confirmed=True,
        ),
    )
    watch = await _one(session, WatchedDomain)
    await processor.on_watch_change(session, watch, ["content_changed"])
    finding = await _one(session, Finding)
    assert finding.category == "clone_site" and finding.match["signal"] == "canary"
    assert "watchlist" in finding.sources and finding.score_breakdown["intel_hits"] == 0


async def test_context_cap_invalid_volume_and_private_url(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    with pytest.raises(ValueError, match="16 KB"):
        await processor.process(session, _item([], "reported", context={"subject": "x" * 17000}))
    result = await processor.process(
        session,
        _item(
            [
                {"type": "url", "value": "http://10.0.0.1/private"},
                {"type": "domain", "value": "clone.top", "volume": "garbage"},
                {"type": "report", "value": ""},
            ],
            "reported",
        ),
    )
    assert result.findings == []


async def test_branded_canary_no_double_intel_and_watched(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    result = await _processor(sbr_rules).process(
        session,
        _item(
            [{"type": "domain", "value": "sbr-loans.com"}],
            "canary",
            source="canary",
            confirmed=True,
        ),
    )
    finding = await _one(session, Finding)
    assert (
        finding.score_breakdown["owned_signal"] == 30 and finding.score_breakdown["intel_hits"] == 0
    )
    assert result.watched == ["sbr-loans.com"]
