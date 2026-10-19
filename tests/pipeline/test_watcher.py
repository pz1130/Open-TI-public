from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.pipeline import watcher

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 4, 8, tzinfo=UTC)


async def _finding(session: AsyncSession, rules: ProjectRules, etype: str, value: str, category: Category,
                   when: datetime) -> None:  # fmt: skip
    await repo.upsert_project(session, rules)
    entity = await repo.upsert_entity(session, etype, value, when)
    score = Score(70, Severity.HIGH, category, {"base": 70})
    await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=score, match={},
                              source="certstream", now=when)  # fmt: skip


async def test_our_and_known_hosts(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    recent, old = NOW - timedelta(days=3), NOW - timedelta(days=90)
    await _finding(session, sbr_rules, "domain", "sbr-loans.com", Category.TYPOSQUAT_DOMAIN, recent)
    await _finding(
        session, sbr_rules, "url", "https://SBR-Pay.top/login", Category.PHISHING_SITE, recent
    )
    await _finding(session, sbr_rules, "domain", "sbr-old.top", Category.TYPOSQUAT_DOMAIN, old)
    await _finding(
        session, sbr_rules, "url", "https://old.sbr-archive.top/login", Category.PHISHING_SITE, old
    )
    await _finding(
        session, sbr_rules, "domain", "sbr-cert.top", Category.UNAPPROVED_CERTIFICATE, recent
    )
    ours = await watcher.our_hosts(
        session, sbr_rules.project, since=NOW - timedelta(days=30), until=NOW
    )
    assert ours == {"sbr-loans.com", "sbr-pay.top"}
    known = await watcher.known_hosts(
        session, sbr_rules.project, ["sbr-old.top", "sbr-archive.top", "sbr-missed.top"]
    )
    assert known == {"sbr-old.top", "sbr-archive.top"}
