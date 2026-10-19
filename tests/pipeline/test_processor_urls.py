from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db import repo
from opti.db.models import Alert, Entity, Finding, WatchedDomain
from opti.pipeline import suppression
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem
from opti.sdk.testing import StaticEnricher, make_context, static_enricher

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
PROJECT = "sample-brand-protection"
LOGIN = {"reachable": True, "status": 200, "has_password_field": True, "brand_terms": ["SBR"]}


def _processor(rules: ProjectRules) -> tuple[Processor, StaticEnricher]:
    ctx = make_context(rules)
    probe = static_enricher(ctx, "http_probe", dict(LOGIN), types=("domain", "url"))
    enrichers = {
        "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "mx": []}),
        "rdap": static_enricher(ctx, "rdap", {"registration": "2026-09-30T00:00:00Z"}),
        "tranco": static_enricher(ctx, "tranco", {"rank": None}),
        "http_probe": probe,
    }
    return Processor(
        rules, EnrichmentService(enrichers, clock=lambda: NOW), clock=lambda: NOW
    ), probe


def _item(
    url: str, *, connector: str = "openphish", confirmed: bool = True, **payload: Any
) -> RawItem:
    body = {"feed_url": url, "intel": {"source": connector, "confirmed": confirmed}, **payload}
    return RawItem(connector, url, NOW, url, body, project_ids=(PROJECT,))


async def _count(session: AsyncSession, model: type) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


async def test_confirmed_host_match_is_phishing_domain(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, _ = _processor(sbr_rules)
    r = await p.process(session, _item("https://sbr-loans.com/login?utm_source=x"))
    assert len(r.findings) == 1 and len(r.alerts) == 1 and r.watched == []
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.category == "phishing_site" and f.score_breakdown["intel_hits"] == 20
    assert f.match["url"] == "https://sbr-loans.com/login"
    e = await session.get(Entity, f.entity_id)
    assert e is not None and (e.type, e.value) == ("domain", "sbr-loans.com")


async def test_path_only_url_creates_url_finding(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, probe = _processor(sbr_rules)
    url = "https://sites.google.com/view/samplebrand-grants"
    r = await p.process(session, _item(url))
    assert len(r.findings) == 1 and len(r.alerts) == 1
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.category == "phishing_site"
    assert f.score == 40 + 15 + 25 + 20 and f.severity == "critical"
    e = await session.get(Entity, f.entity_id)
    assert e is not None and (e.type, e.value) == ("url", url)
    assert e.enrichment["dns"]["target_type"] == "domain"
    assert e.enrichment["dns"]["target_value"] == "sites.google.com"
    assert e.enrichment["rdap"]["target_value"] == "sites.google.com"
    assert probe.calls == [url]  # 探测的是这个 URL，而不是 sites.google.com 首页
    domains = (await session.scalars(select(Entity.value).where(Entity.type == "domain"))).all()
    assert "google.com" not in domains and "sites.google.com" not in domains
    assert await _count(session, WatchedDomain) == 0
    alert = (await session.scalars(select(Alert))).one()
    assert alert.routing["domain"] == url and alert.evidence_status == "pending"


async def test_unconfirmed_url_scores_without_intel(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, _ = _processor(sbr_rules)
    r = await p.process(
        session, _item("https://evil.top/sbr/login", connector="urlscan", confirmed=False)
    )
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.score_breakdown["intel_hits"] == 0


async def test_official_and_unmatched_urls_are_ignored(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, _ = _processor(sbr_rules)
    for url in (
        "https://sbr.int/careers/sbr",
        "https://example.org/news",
        "https://www.sbrbank.com/sbr",
    ):
        r = await p.process(session, _item(url))
        assert r.findings == [] and r.alerts == [], url
    assert await _count(session, Finding) == 0


async def test_same_target_from_two_feeds_one_alert(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, _ = _processor(sbr_rules)
    await p.process(session, _item("https://sbr-loans.com/a", connector="openphish"))
    await p.process(session, _item("https://sbr-loans.com/a", connector="openphish"))  # 重放
    await p.process(
        session, _item("https://sbr-loans.com/b", connector="phishtank")
    )  # 另一来源、同一主机
    assert await _count(session, Finding) == 1
    assert await _count(session, Alert) == 1
    f = (await session.scalars(select(Finding))).one()
    assert sorted(f.sources) == ["openphish", "phishtank"]


async def test_suppressed_host_skips_url(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    p, probe = _processor(sbr_rules)
    await repo.upsert_project(session, sbr_rules)
    await suppression.create_rule(
        session,
        project_id=PROJECT,
        kind="registered_domain",
        value="evil.top",
        reason="测试站",
        now=NOW,
    )
    r = await p.process(session, _item("https://evil.top/sbr/login"))
    assert r.suppressed == ["https://evil.top/sbr/login"] and r.findings == []
    assert probe.calls == []


async def test_userinfo_feed_survives_normalization(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    from opti.connectors.urlfeed import UrlFeedScanner
    from opti.sdk.plan import build_query_plan

    item = next(
        UrlFeedScanner("openphish", sbr_rules).scan(
            [
                ("https://sbr.int:never-store-this@evil.top/login", {"confirmed": True}),
            ],
            build_query_plan(sbr_rules),
        )
    )
    p, probe = _processor(sbr_rules)
    r = await p.process(session, item)
    assert len(r.findings) == 1
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.score_breakdown["url_brand"] == 20
    assert probe.calls == ["https://evil.top/login"]
    assert "never-store-this" not in str(f.match)


async def test_collector_kind_and_context_cannot_change_target(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, _ = _processor(sbr_rules)
    r = await p.process(session, _item("https://evil.top/sbr/login", kind="domain"))
    f = await session.get(Finding, r.findings[0])
    assert f is not None
    e = await session.get(Entity, f.entity_id)
    assert e is not None and e.type == "url"
    ignored = await p.process(
        session, _item("https://example.org/news", match_input="https://sbr@evil.top/login")
    )
    assert ignored.findings == []


async def test_host_finding_probes_exact_paths_with_separate_cache(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, probe = _processor(sbr_rules)
    a = "https://sbr-loans.com/a"
    b = "https://sbr-loans.com/b"
    first = await p.process(session, _item(a))
    second = await p.process(session, _item(b, connector="phishtank"))
    assert first.findings == second.findings
    assert probe.calls == [a, b]
    alert = await session.get(Alert, first.alerts[0])
    assert alert is not None and alert.routing["url"] == a
    f = await session.get(Finding, first.findings[0])
    assert f is not None and f.match["url"] == b


async def test_shared_host_has_distinct_url_findings(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    p, _ = _processor(sbr_rules)
    first = await p.process(session, _item("https://sites.google.com/view/sbr-grants"))
    second = await p.process(session, _item("https://sites.google.com/view/sbr-loans"))
    assert first.findings != second.findings
    assert await _count(session, Finding) == 2
    assert await _count(session, Alert) == 2
    domains = list(await session.scalars(select(Entity).where(Entity.type == "domain")))
    assert domains == []


async def test_confirmed_is_strict_boolean(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    p, _ = _processor(sbr_rules)
    item = _item("https://evil.top/sbr", intel={"confirmed": "false"})
    r = await p.process(session, item)
    f = await session.get(Finding, r.findings[0])
    assert f is not None and f.score_breakdown["intel_hits"] == 0
