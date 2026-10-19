from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, AppUser, Entity, Finding

POINTS = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}


@dataclass
class Seeded:
    alert: Alert
    finding: Finding
    entity: Entity


@pytest.fixture
def seed(session: AsyncSession, sbr_rules: ProjectRules) -> Callable[..., Awaitable[Seeded]]:
    async def make(
        value: str = "sbr-loans.com", *, entity_type: str = "domain", severity: str = "high",
        category: str = "typosquat_domain", enrichment: dict[str, Any] | None = None,
    ) -> Seeded:  # fmt: skip
        now = datetime.now(UTC)
        await repo.upsert_project(session, sbr_rules)
        entity = await repo.upsert_entity(session, entity_type, value, now)
        if enrichment is not None:
            entity.enrichment = enrichment
        points = POINTS[severity]
        up = await repo.upsert_finding(
            session, project_id=sbr_rules.project, entity=entity,
            score=Score(points, Severity(severity), Category(category), {"base": points}),
            match={"domain": value, "reasons": []}, source="certstream", now=now,
        )  # fmt: skip
        alert = await repo.open_alert(session, up.finding, Severity(severity), now)
        await session.flush()
        return Seeded(alert, up.finding, entity)

    return make


@pytest.fixture
def make_user(session: AsyncSession) -> Callable[[str], Awaitable[int]]:
    async def make(username: str) -> int:
        user = AppUser(
            username=username, password_hash="!", roles=["responder"], created_at=datetime.now(UTC)
        )
        session.add(user)
        await session.flush()
        return user.id

    return make
