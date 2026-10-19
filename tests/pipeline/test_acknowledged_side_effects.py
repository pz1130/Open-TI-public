from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import ExposedAccount
from opti.exposure import service as exposure_service
from opti.tickets import service as ticket_service
from opti.tickets.config import TicketsConfig

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 4, 8, 0, tzinfo=UTC)


async def _alert(session: AsyncSession, rules: ProjectRules, category: Category, domain: str):
    await repo.upsert_project(session, rules)
    entity = await repo.upsert_entity(session, "domain", domain, NOW)
    up = await repo.upsert_finding(
        session,
        project_id=rules.project,
        entity=entity,
        score=Score(80, Severity.HIGH, category, {}),
        match={},
        source="test",
        now=NOW,
    )
    alert = await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
    alert.status = "acknowledged"
    await session.flush()
    return alert, up.finding


async def test_acknowledgement_keeps_ticket_and_exposure_push_pending(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ticket, _ = await _alert(session, sbr_rules, Category.TYPOSQUAT_DOMAIN, "sbr-loans.com")
    exposure, finding = await _alert(
        session, sbr_rules, Category.CREDENTIAL_EXPOSURE, "sbr-exposure.com"
    )
    session.add(
        ExposedAccount(
            project_id=sbr_rules.project,
            finding_id=finding.id,
            email="staff@example.org",
            source="test",
            first_seen=NOW,
            last_seen=NOW,
        )
    )
    await session.flush()
    config = TicketsConfig(auto_push=(Severity.HIGH,))
    pending = await ticket_service.next_auto_push(session, config, NOW, exclude=[])
    assert pending is not None and pending.id == ticket.id
    selected = await exposure_service.next_auto_push(session, config, NOW, exclude=[])
    assert selected is not None and selected[0].id == exposure.id
