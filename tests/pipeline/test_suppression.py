from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db import repo
from opti.db.models import Alert, Finding, RawItemRow, SuppressionRule, WatchedDomain
from opti.pipeline import suppression
from opti.pipeline import watchlist as wl
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem
from opti.sdk.testing import make_context, static_enricher

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
PROJECT = "sample-brand-protection"


def test_normalize_value() -> None:
    assert suppression.normalize_value("domain", " Login.SBR-Loans.com. ") == "login.sbr-loans.com"
    assert (
        suppression.normalize_value("registered_domain", "login.sbr-loans.com") == "sbr-loans.com"
    )
    with pytest.raises(suppression.SuppressionError):
        suppression.normalize_value("domain", "not a domain")
    with pytest.raises(suppression.SuppressionError):
        suppression.normalize_value("regex", "sbr-loans.com")


async def _rule(
    session: AsyncSession, rules: ProjectRules, kind: str, value: str, **kw: Any
) -> int:
    await repo.upsert_project(session, rules)
    rule = await suppression.create_rule(
        session,
        project_id=rules.project,
        kind=kind,
        value=value,
        reason="SBR Bank PLC",
        now=NOW,
        **kw,
    )
    return rule.id


async def _active(session: AsyncSession, domain: str, registered: str, now: datetime = NOW) -> bool:
    found = await suppression.find_active(
        session, PROJECT, domain=domain, registered=registered, now=now
    )
    return found is not None


@pytest.mark.db
async def test_registered_rule_covers_subdomains_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _rule(session, sbr_rules, "registered_domain", "sbr-loans.com")
    assert await _active(session, "sbr-loans.com", "sbr-loans.com")
    assert await _active(session, "login.sbr-loans.com", "sbr-loans.com")
    assert not await _active(session, "sbr-loans.top", "sbr-loans.top")
    assert not await _active(session, "sbr-loans.com.evil.top", "evil.top")


@pytest.mark.db
async def test_domain_rule_matches_exact_host(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _rule(session, sbr_rules, "domain", "login.sbr-loans.com")
    assert await _active(session, "login.sbr-loans.com", "sbr-loans.com")
    assert not await _active(session, "sbr-loans.com", "sbr-loans.com")


@pytest.mark.db
async def test_expired_and_revoked_rules_are_ignored(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _rule(session, sbr_rules, "domain", "a-sbr.com", expires_at=NOW + timedelta(days=1))
    assert await _active(session, "a-sbr.com", "a-sbr.com")
    assert not await _active(session, "a-sbr.com", "a-sbr.com", NOW + timedelta(days=2))
    rid = await _rule(session, sbr_rules, "domain", "b-sbr.com")
    revoked = await suppression.revoke(session, rid, user_id=None, now=NOW)
    assert revoked is not None and revoked.revoked_at == NOW
    assert not await _active(session, "b-sbr.com", "b-sbr.com")
    assert await suppression.revoke(session, rid, user_id=None, now=NOW) is None


@pytest.mark.db
async def test_rule_expires_matching_watch_entries(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    for d in ("sbr-loans.com", "login.sbr-loans.com", "sbr-loans.top"):
        await wl.ensure_watched(session, PROJECT, d, reason="t", now=NOW)
    await _rule(session, sbr_rules, "registered_domain", "sbr-loans.com")
    rows = {
        w.domain: (w.expires_at, w.paused_by_suppression)
        for w in (await session.scalars(select(WatchedDomain))).all()
    }
    assert rows == {
        "sbr-loans.com": (None, True),
        "login.sbr-loans.com": (None, True),
        "sbr-loans.top": (None, False),
    }


@pytest.mark.db
async def test_expired_rule_restores_paused_watch(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    domain = "sbr-loans.com"
    await wl.ensure_watched(session, PROJECT, domain, reason="t", now=NOW)
    await _rule(session, sbr_rules, "domain", domain, expires_at=NOW + timedelta(hours=1))
    row = (await session.scalars(select(WatchedDomain))).one()
    assert row.paused_by_suppression and row.expires_at is None
    assert await wl.due(session, NOW + timedelta(hours=2)) == []
    restored = await suppression.restore_paused(session, now=NOW + timedelta(hours=2))
    await session.refresh(row)
    assert restored == 1 and row.expires_at is None
    assert not row.paused_by_suppression and row.state == "unknown"
    assert [w.domain for w in await wl.due(session, NOW + timedelta(hours=2))] == [domain]


@pytest.mark.db
async def test_revoke_restores_only_when_no_other_active_rule(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    domain = "login.sbr-loans.com"
    await wl.ensure_watched(session, PROJECT, domain, reason="t", now=NOW)
    first = await _rule(session, sbr_rules, "domain", domain)
    second = await _rule(session, sbr_rules, "registered_domain", "sbr-loans.com")
    assert await suppression.revoke(session, first, user_id=None, now=NOW)
    row = (await session.scalars(select(WatchedDomain))).one()
    await session.refresh(row)
    assert row.paused_by_suppression
    assert await suppression.revoke(session, second, user_id=None, now=NOW)
    await session.refresh(row)
    assert not row.paused_by_suppression and row.expires_at is None


@pytest.mark.db
async def test_suppression_preserves_finite_watch_expiry(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    until = NOW + timedelta(days=90)
    await wl.watch_until(session, PROJECT, "sbr-loans.com", reason="takedown", now=NOW, until=until)
    rule_id = await _rule(session, sbr_rules, "domain", "sbr-loans.com")
    row = (await session.scalars(select(WatchedDomain))).one()
    await session.refresh(row)
    assert row.paused_by_suppression and row.expires_at == until
    assert await suppression.revoke(session, rule_id, user_id=None, now=NOW)
    await session.refresh(row)
    assert not row.paused_by_suppression and row.expires_at == until


@pytest.mark.db
async def test_processor_skips_suppressed_domain(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ctx = make_context(sbr_rules)
    probe = static_enricher(ctx, "http_probe", {"reachable": False})
    enrichers = {
        "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "mx": []}),
        "rdap": static_enricher(ctx, "rdap", {"registration": "2026-09-30T00:00:00Z"}),
        "tranco": static_enricher(ctx, "tranco", {"rank": None}),
        "http_probe": probe,
    }
    processor = Processor(
        sbr_rules, EnrichmentService(enrichers, clock=lambda: NOW), clock=lambda: NOW
    )
    await _rule(session, sbr_rules, "registered_domain", "sbr-loans.com")
    item = RawItem(
        "certstream",
        "p1",
        NOW,
        None,
        {"matches": [{"domain": "sbr-loans.com"}]},
        project_ids=(PROJECT,),
    )
    result = await processor.process(session, item)
    assert result.stored and result.suppressed == ["sbr-loans.com"]
    assert result.findings == [] and result.alerts == [] and result.watched == []
    assert probe.calls == []  # 被抑制的域名不再富化（不访问可疑站点、不耗第三方额度）
    for model in (Finding, Alert, WatchedDomain):
        assert await session.scalar(select(func.count()).select_from(model)) == 0
    assert await session.scalar(select(func.count()).select_from(RawItemRow)) == 1


async def _open_alert(session: AsyncSession, rules: ProjectRules, domain: str) -> int:
    from opti.core.scoring import Category, Score, Severity

    entity = await repo.upsert_entity(session, "domain", domain, NOW)
    score = Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 20})
    up = await repo.upsert_finding(
        session, project_id=rules.project, entity=entity, score=score, match={},
        source="certstream", now=NOW,
    )  # fmt: skip
    return (await repo.open_alert(session, up.finding, Severity.HIGH, NOW)).id


@pytest.mark.db
async def test_close_covered_alerts(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    """建立规则后，规则覆盖的其他未结告警一并关闭：否则仍会推送到 Teams、仍会去截图。"""
    await repo.upsert_project(session, sbr_rules)
    source = await _open_alert(session, sbr_rules, "sbr-loans.com")
    sibling = await _open_alert(session, sbr_rules, "login.sbr-loans.com")
    other = await _open_alert(session, sbr_rules, "sbr-loans.top")
    rid = await _rule(session, sbr_rules, "registered_domain", "sbr-loans.com")
    rule = await session.get(SuppressionRule, rid)
    assert rule is not None
    closed = await suppression.close_covered_alerts(session, rule, now=NOW, exclude_alert_id=source)
    assert closed == [sibling]
    status = {
        a.id: (a.status, a.triage_verdict) for a in (await session.scalars(select(Alert))).all()
    }
    assert status[sibling] == ("closed", "suppressed")
    assert status[source][0] == "open" and status[other][0] == "open"
