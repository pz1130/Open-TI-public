from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.reports import empty_content
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, ConnectorRun, Report
from opti.pipeline import retention
from opti.pipeline.retention import RetentionConfig

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 12, tzinfo=UTC)


async def _finding(
    session: AsyncSession,
    rules: ProjectRules,
    domain: str,
    days_ago: int,
    *,
    alert: bool = False,
    closed: bool = True,
) -> None:
    at = NOW - timedelta(days=days_ago)
    entity = await repo.upsert_entity(session, "domain", domain, at)
    up = await repo.upsert_finding(
        session,
        project_id=rules.project,
        entity=entity,
        score=Score(80, Severity.HIGH, Category.PHISHING_SITE, {}),
        match={"context": {"contact": "a@example.org"}},
        source="test",
        now=at,
    )
    if alert:
        opened = await repo.open_alert(session, up.finding, Severity.HIGH, at)
        if closed:
            row = await session.get(Alert, opened.id)
            assert row is not None
            row.status = "closed"


async def _seed(session: AsyncSession, rules: ProjectRules) -> None:
    await repo.upsert_project(session, rules)
    await _finding(session, rules, "old-noalert.example", 400)
    await _finding(session, rules, "new-noalert.example", 60)
    await _finding(session, rules, "old-case.example", 1200, alert=True)
    await _finding(session, rules, "old-open-case.example", 1200, alert=True, closed=False)
    session.add(
        ConnectorRun(connector_id="crtsh", started_at=NOW - timedelta(days=100), status="ok")
    )
    start = NOW - timedelta(days=400)
    session.add(
        Report(
            project_id=rules.project,
            kind="daily",
            period_start=start,
            period_end=start,
            created_at=start,
            content=empty_content("daily", start=start, end=start),
            sent_sinks=[],
        )
    )
    await session.flush()


async def test_preview_matches_next_apply(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _seed(session, sbr_rules)
    cfg = RetentionConfig(report_contacts_days=30)
    preview = await retention.preview(session, cfg, now=NOW)
    assert set(preview) == set(retention.PREVIEW_KEYS)
    assert (preview["findings"], preview["cases"]) == (1, 1)
    assert await retention.preview(session, cfg, now=NOW) == preview
    actual = await retention.apply(session, cfg, now=NOW)
    assert preview["findings"] + preview["cases"] == actual.counts["findings"]
    for key in (
        "alerts",
        "evidence",
        "takedowns",
        "connector_runs",
        "reports",
        "report_contacts",
        "exposed_accounts",
        "documents",
    ):
        assert preview[key] == actual.counts[key], key


async def test_shorter_retention_previews_more(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await _seed(session, sbr_rules)
    long = await retention.preview(session, RetentionConfig(), now=NOW)
    short = await retention.preview(session, RetentionConfig(findings_days=30), now=NOW)
    assert short["findings"] == long["findings"] + 1


async def test_preview_reports_when_findings_exceed_one_batch(
    session: AsyncSession, sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _seed(session, sbr_rules)  # 到期可删的发现有 2 个
    cfg = RetentionConfig()
    original = retention.policy.current()
    monkeypatch.setattr(
        retention.policy,
        "_current",
        original.model_copy(
            update={
                "batches": original.batches.model_copy(update={"retention": 1}),
            }
        ),
    )
    assert (await retention.preview(session, cfg, now=NOW))["findings"] + (
        await retention.preview(session, cfg, now=NOW)
    )["cases"] == 1
    assert await retention.exceeds_batch(session, cfg, now=NOW) is True
    monkeypatch.setattr(
        retention.policy,
        "_current",
        original.model_copy(
            update={
                "batches": original.batches.model_copy(update={"retention": 2}),
            }
        ),
    )
    assert await retention.exceeds_batch(session, cfg, now=NOW) is False
