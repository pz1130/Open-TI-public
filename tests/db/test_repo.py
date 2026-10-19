import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.cursors import PgCursorStore
from opti.db.models import AppUser, ConnectorRun, Finding, FindingObservation
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
PROJECT = "sample-brand-protection"
MEDIUM = Score(43, Severity.MEDIUM, Category.TYPOSQUAT_DOMAIN, {"base": 20})
CRITICAL = Score(93, Severity.CRITICAL, Category.PHISHING_SITE, {"base": 40})


def _item(source_id: str = "p1", connector: str = "certstream") -> RawItem:
    return RawItem(connector, source_id, NOW, None, {"x": 1}, project_ids=(PROJECT,))


async def _finding(
    session: AsyncSession, rules: ProjectRules, score: Score = MEDIUM
) -> repo.FindingUpsert:
    await repo.upsert_project(session, rules)
    e = await repo.upsert_entity(session, "domain", "sbr-loans.com", NOW)
    return await repo.upsert_finding(
        session, project_id=PROJECT, entity=e, score=score, match={}, source="certstream", now=NOW
    )


async def test_raw_item_insert_is_idempotent(session: AsyncSession) -> None:
    assert await repo.insert_raw_item(session, _item()) is True
    assert await repo.insert_raw_item(session, _item()) is False


async def test_upsert_entity_updates_last_seen(session: AsyncSession) -> None:
    e1 = await repo.upsert_entity(session, "domain", "sbr-loans.com", NOW)
    later = NOW + timedelta(hours=1)
    e2 = await repo.upsert_entity(session, "domain", "sbr-loans.com", later)
    assert e1.id == e2.id and e2.first_seen == NOW and e2.last_seen == later


async def test_upsert_finding_escalation(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    up1 = await _finding(session, sbr_rules)
    assert up1.created and up1.escalated
    e = await repo.upsert_entity(session, "domain", "sbr-loans.com", NOW)
    kw = {"project_id": PROJECT, "entity": e, "match": {}, "now": NOW}
    up2 = await repo.upsert_finding(session, score=MEDIUM, source="certstream", **kw)
    assert not up2.created and not up2.escalated
    up3 = await repo.upsert_finding(session, score=CRITICAL, source="certstream", **kw)
    assert up3.escalated and up3.finding.category == "phishing_site"
    up4 = await repo.upsert_finding(session, score=MEDIUM, source="crtsh", **kw)
    assert not up4.escalated and up4.finding.severity == "medium"
    assert set(up4.finding.sources) == {"certstream", "crtsh"}
    assert await session.scalar(select(func.count()).select_from(Finding)) == 1


async def test_upsert_finding_takes_update_path_on_conflict(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    e = await repo.upsert_entity(session, "domain", "sbr-loans.com", NOW)
    session.add(
        Finding(
            project_id=PROJECT, entity_id=e.id, category="typosquat_domain", score=20,
            severity="low", status="new", score_breakdown={}, match={}, sources=["other"],
            first_seen=NOW, last_seen=NOW,
        )
    )  # fmt: skip
    await session.flush()
    up = await repo.upsert_finding(
        session, project_id=PROJECT, entity=e, score=MEDIUM, match={}, source="certstream", now=NOW
    )
    assert not up.created and up.escalated and up.finding.severity == "medium"


async def test_observation_recorded_once(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    up = await _finding(session, sbr_rules)
    await repo.add_observation(session, up.finding, _item(), 43, NOW)
    await repo.add_observation(session, up.finding, _item(), 43, NOW)
    assert await session.scalar(select(func.count()).select_from(FindingObservation)) == 1


async def test_open_alert_supersedes_previous(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    up = await _finding(session, sbr_rules)
    a1 = await repo.open_alert(session, up.finding, Severity.MEDIUM, NOW)
    assert a1.routing["attack_techniques"][0]["id"] == "T1583.001"
    a2 = await repo.open_alert(session, up.finding, Severity.CRITICAL, NOW)
    await session.refresh(a1)
    assert a1.status == "superseded" and a2.status == "open" and a2.severity == "critical"


async def test_acknowledged_alert_is_superseded_and_assignee_follows(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    up = await _finding(session, sbr_rules)
    user = AppUser(username="analyst", password_hash="unused", roles=["analyst"], created_at=NOW)
    session.add(user)
    await session.flush()
    old = await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
    old.status = "acknowledged"
    old.assignee_id = user.id
    await session.flush()
    new = await repo.open_alert(session, up.finding, Severity.CRITICAL, NOW)
    await session.refresh(old)
    assert old.status == "superseded"
    assert new.status == "open" and new.assignee_id == user.id


async def test_unchanged_project_does_not_hold_global_write_lock(
    clean_db: str, sbr_rules: ProjectRules
) -> None:
    engine = create_async_engine(clean_db)
    try:
        async with AsyncSession(engine) as setup, setup.begin():
            await repo.upsert_project(setup, sbr_rules)
        async with AsyncSession(engine) as first, first.begin():
            await repo.upsert_project(first, sbr_rules)
            async with AsyncSession(engine) as second, second.begin():
                await asyncio.wait_for(repo.upsert_project(second, sbr_rules), timeout=2)
    finally:
        await engine.dispose()


async def test_connector_run(session: AsyncSession) -> None:
    run_id = await repo.start_run(session, "crtsh", NOW)
    await repo.finish_run(session, run_id, status="ok", items=3, errors=0, message="", now=NOW)
    run = await session.get(ConnectorRun, run_id)
    assert run is not None and run.status == "ok" and run.items == 3 and run.ended_at == NOW


async def test_pg_cursor_store_roundtrip(session: AsyncSession) -> None:
    store = PgCursorStore()
    store.set("crtsh", "max_id:sbr%", "1002")
    assert await store.flush(session, NOW) == 1
    assert await store.flush(session, NOW) == 0
    other = PgCursorStore()
    await other.load(session, "crtsh")
    assert other.get("crtsh", "max_id:sbr%") == "1002"
    other.set("crtsh", "max_id:sbr%", "2000")
    await other.flush(session, NOW)
    third = PgCursorStore()
    await third.load(session, "crtsh")
    assert third.get("crtsh", "max_id:sbr%") == "2000"
