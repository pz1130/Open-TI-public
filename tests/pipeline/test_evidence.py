from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, Entity, Evidence
from opti.pipeline import evidence
from opti.pipeline.enrichment import EnrichmentService
from opti.sdk.testing import make_context, static_enricher
from opti.storage.artifacts import store_saver
from opti.storage.objects import MemoryObjectStore
from opti.takedown.config import Platform, TakedownConfig

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
SHOT = {
    "final_url": "https://sbr-loans.com/login", "captured_at": "2026-10-02T08:01:00+00:00",
    "method": "opti-sandbox/0.1.0 (chromium 140.0)",
    "artifacts": [
        {"name": "screenshot", "content_type": "image/png", "data_b64": "iVBORw0KGgo="},
        {"name": "html", "content_type": "text/html", "data_b64": "PGh0bWw+"},
    ],
}  # fmt: skip


async def _alert(
    session: AsyncSession, rules: ProjectRules, domain: str, severity: Severity,
    category: Category = Category.TYPOSQUAT_DOMAIN,
) -> Alert:  # fmt: skip
    await repo.upsert_project(session, rules)
    e = await repo.upsert_entity(session, "domain", domain, NOW)
    score = Score(90 if severity == Severity.HIGH else 50, severity, category, {})
    up = await repo.upsert_finding(
        session,
        project_id=rules.project,
        entity=e,
        score=score,
        match={},
        source="certstream",
        now=NOW,
    )
    return await repo.open_alert(session, up.finding, severity, NOW)


async def test_only_high_domain_alerts_need_evidence(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    assert (
        await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    ).evidence_status == "pending"
    assert (
        await _alert(session, sbr_rules, "sbr-portal.top", Severity.MEDIUM)
    ).evidence_status == "none"
    cert = await _alert(
        session, sbr_rules, "mail.sbr.int", Severity.HIGH, Category.UNAPPROVED_CERTIFICATE
    )
    assert cert.evidence_status == "none"


async def test_capture_stores_evidence_chain(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    store = MemoryObjectStore()
    icon = {"method": "mmh3-rfc2045-base64", "hash": -123456, "reference_matches": ["官网"]}
    shot = static_enricher(make_context(sbr_rules), "screenshot", {**SHOT, "favicon": icon}, ttl=0)
    svc = EnrichmentService({"screenshot": shot}, saver=store_saver(store))
    alert = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    pending = await evidence.next_pending(session)
    assert pending is not None and pending.id == alert.id
    assert await evidence.capture(session, pending, svc, NOW)
    rows = (await session.scalars(select(Evidence).order_by(Evidence.kind))).all()
    assert [(r.kind, r.content_type) for r in rows] == [
        ("html", "text/html"),
        ("screenshot", "image/png"),
    ]
    shot_row = rows[1]
    assert shot_row.alert_id == alert.id and shot_row.node_id == "local"
    assert shot_row.captured_at == datetime(2026, 10, 2, 8, 1, tzinfo=UTC)
    assert shot_row.method == "opti-sandbox/0.1.0 (chromium 140.0)"
    assert shot_row.source_url == "https://sbr-loans.com/login"
    assert store.objects[shot_row.object_key].startswith(b"\x89PNG")
    assert await evidence.verify(session, store, shot_row.id)
    assert alert.evidence_status == "done"
    assert await evidence.next_pending(session) is None
    entity = await session.scalar(select(Entity).where(Entity.value == "sbr-loans.com"))
    assert entity is not None and "data_b64" not in str(entity.enrichment)
    assert entity.enrichment["screenshot"]["data"]["favicon"] == icon


async def test_verify_detects_tampering(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    store = MemoryObjectStore()
    svc = EnrichmentService(
        {"screenshot": static_enricher(make_context(sbr_rules), "screenshot", SHOT, ttl=0)},
        saver=store_saver(store),
    )
    alert = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    await evidence.capture(session, alert, svc, NOW)
    row = (await session.scalars(select(Evidence).limit(1))).one()
    store.objects[row.object_key] = b"tampered"
    assert not await evidence.verify(session, store, row.id)


async def test_capture_failure_retries_then_gives_up(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    failing = static_enricher(
        make_context(sbr_rules), "screenshot", {"error": "navigation: timeout"}, ttl=0
    )
    svc = EnrichmentService({"screenshot": failing}, saver=store_saver(MemoryObjectStore()))
    alert = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    for attempt in range(1, evidence.MAX_ATTEMPTS + 1):
        assert not await evidence.capture(session, alert, svc, NOW)
        assert alert.evidence_attempts == attempt
    assert alert.evidence_status == "failed"
    assert await evidence.next_pending(session) is None


async def test_next_pending_skips_excluded(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    a = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    b = await _alert(session, sbr_rules, "sbr-grant.top", Severity.HIGH)
    nxt = await evidence.next_pending(session, exclude=[a.id])
    assert nxt is not None and nxt.id == b.id


async def test_acknowledged_alert_still_gets_pending_evidence(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    alert = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    alert.status = "acknowledged"
    await session.flush()
    pending = await evidence.next_pending(session)
    assert pending is not None and pending.id == alert.id


async def test_domain_alert_captures_frozen_feed_url(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    alert = await _alert(session, sbr_rules, "sbr-loans.com", Severity.HIGH)
    original = "https://sbr-loans.com/original-login"
    alert.routing = {**alert.routing, "url": original}
    entity = (await session.scalars(select(Entity))).one()
    # A later observation must not change the evidence target for this alert.
    from opti.db.models import Finding

    finding = (await session.scalars(select(Finding))).one()
    finding.match = {"url": "https://sbr-loans.com/later-login"}
    shot = static_enricher(
        make_context(sbr_rules),
        "screenshot",
        {**SHOT, "final_url": original},
        types=("domain", "url"),
        ttl=0,
    )
    svc = EnrichmentService({"screenshot": shot}, saver=store_saver(MemoryObjectStore()))
    assert await evidence.capture(session, alert, svc, NOW)
    assert shot.calls == [original]
    assert entity.type == "domain"
    assert {r.source_url for r in await session.scalars(select(Evidence))} == {original}


async def test_url_entity_can_capture_evidence(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    url = "https://sites.google.com/view/sbr-grants"
    entity = await repo.upsert_entity(session, "url", url, NOW)
    up = await repo.upsert_finding(
        session,
        project_id=sbr_rules.project,
        entity=entity,
        score=Score(75, Severity.HIGH, Category.PHISHING_SITE, {}),
        match={"url": url},
        source="openphish",
        now=NOW,
    )
    alert = await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
    shot = static_enricher(
        make_context(sbr_rules), "screenshot", {**SHOT, "final_url": url}, types=("url",), ttl=0
    )
    store = MemoryObjectStore()
    assert await evidence.capture(
        session, alert, EnrichmentService({"screenshot": shot}, saver=store_saver(store)), NOW
    )
    assert shot.calls == [url]
    for row in await session.scalars(select(Evidence)):
        assert row.source_url == url
        assert await evidence.verify(session, store, row.id)


async def test_platform_url_is_never_sent_to_screenshot_enricher(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    url = "https://www.linkedin.com/in/fake-ceo/"
    entity = await repo.upsert_entity(session, "url", url, NOW)
    up = await repo.upsert_finding(
        session,
        project_id=sbr_rules.project,
        entity=entity,
        score=Score(75, Severity.HIGH, Category.PHISHING_SITE, {}),
        match={"url": url},
        source="openphish",
        now=NOW,
    )
    alert = await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
    assert alert.evidence_status == "pending"
    shot = static_enricher(make_context(sbr_rules), "screenshot", SHOT, types=("url",), ttl=0)
    svc = EnrichmentService({"screenshot": shot}, saver=store_saver(MemoryObjectStore()))
    cfg = TakedownConfig(
        platforms=(Platform(id="linkedin", name="LinkedIn", hosts=("linkedin.com",)),)
    )
    assert not await evidence.capture(session, alert, svc, NOW, takedown=cfg)
    assert shot.calls == [] and alert.evidence_status == "none"
