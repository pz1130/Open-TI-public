from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api import security
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import (
    AccountCandidate,
    Adjudication,
    Alert,
    AlertFinding,
    Campaign,
    CampaignMember,
    ConnectorRun,
    DomainObservation,
    Evidence,
    Finding,
    ProtectedAccount,
    Report,
    SuppressionRule,
    Takedown,
    TakedownEvent,
    WatchedDomain,
)
from opti.pipeline.retention import (
    RetentionConfig,
    apply,
    load_retention_config,
    preview,
    purge_findings,
    purge_report_contacts,
)

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


async def test_watch_screenshot_retention_preserves_shared_file_version(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    watched = WatchedDomain(
        project_id=sbr_rules.project,
        domain="sbr.example",
        reason="test",
        created_at=NOW,
        next_check_at=NOW,
    )
    session.add(watched)
    await session.flush()
    old = NOW - timedelta(days=31)
    observations = [
        DomainObservation(
            watched_domain_id=watched.id,
            observed_at=at,
            state="parked",
            fingerprint={},
            changes=[],
            data={},
        )
        for at in [old, NOW]
    ]
    session.add_all(observations)
    await session.flush()
    session.add_all(
        [
            Evidence(
                finding_id=None,
                watch_observation_id=obs.id,
                kind="screenshot",
                object_key="evidence/shared.png",
                sha256="a" * 64,
                size=20,
                content_type="image/png",
                captured_at=obs.observed_at,
                method="test",
                node_id="local",
                version_id="v1",
            )
            for obs in observations
        ]
    )
    await session.flush()
    cfg = RetentionConfig(findings_days=30)
    assert (await preview(session, cfg, now=NOW))["evidence"] == 1
    first = await apply(session, cfg, now=NOW)
    assert first.counts["evidence"] == 1 and first.objects == []
    assert len((await session.scalars(select(Evidence))).all()) == 1
    second = await apply(session, cfg, now=NOW + timedelta(days=31))
    assert second.counts["evidence"] == 1 and second.objects == [("evidence/shared.png", "v1")]


async def _finding(
    session: AsyncSession, rules: ProjectRules, value: str, first_seen: datetime
) -> int:
    await repo.upsert_project(session, rules)
    e = await repo.upsert_entity(session, "report", value, first_seen)
    up = await repo.upsert_finding(
        session, project_id=rules.project, entity=e,
        score=Score(60, Severity.MEDIUM, Category.REPORTED_PHISHING, {"base": 45, "owned_signal": 15}),
        match={"signal": "reported", "context": {"description": "贷款诈骗", "contact": "tel:+86-000"}},
        source="public_report", now=first_seen,
    )  # fmt: skip
    return up.finding.id


async def test_report_contact_is_purged(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    old = await _finding(session, sbr_rules, "r-old", NOW - timedelta(days=91))
    new = await _finding(session, sbr_rules, "r-new", NOW - timedelta(days=5))
    assert await purge_report_contacts(session, NOW - timedelta(days=90)) == 1
    session.expire_all()
    f_old, f_new = await session.get(Finding, old), await session.get(Finding, new)
    assert f_old is not None and f_old.match["context"] == {
        "description": "贷款诈骗",
        "contact": None,
    }
    assert f_new is not None and f_new.match["context"]["contact"] == "tel:+86-000"
    assert await purge_report_contacts(session, NOW - timedelta(days=90)) == 0  # 幂等


async def test_raw_contacts_purged_but_content_retained(session: AsyncSession) -> None:
    from sqlalchemy import select

    from opti.db.models import RawItemRow
    from opti.sdk.models import RawItem

    old = NOW - timedelta(days=91)
    item = RawItem(
        "public_report",
        "old-raw",
        old,
        None,
        {"context": {"contact": "private@example.org", "description": "report"}},
    )
    await repo.insert_raw_item(session, item)
    assert await purge_report_contacts(session, NOW - timedelta(days=90)) == 0
    row = (await session.scalars(select(RawItemRow))).one()
    assert row.payload["context"] == {"contact": None, "description": "report"}


async def _case(session: AsyncSession, rules: ProjectRules, value: str, *, last_seen: datetime,
                alert_status: str | None = "closed") -> tuple[int, int | None]:  # fmt: skip
    await repo.upsert_project(session, rules)
    e = await repo.upsert_entity(session, "domain", value, last_seen)
    score = Score(70 if alert_status else 25, Severity.HIGH if alert_status else Severity.LOW,
                  Category.TYPOSQUAT_DOMAIN, {"base": 20})  # fmt: skip
    up = await repo.upsert_finding(session, project_id=rules.project, entity=e, score=score, match={},
                                   source="certstream", now=last_seen)  # fmt: skip
    if alert_status is None:
        return up.finding.id, None
    alert = await repo.open_alert(session, up.finding, score.severity, last_seen)
    alert.status = alert_status
    return up.finding.id, alert.id


def _takedown(rules: ProjectRules, finding_id: int, alert_id: int, user_id: int, state: str,
              *, resolved: datetime | None = None, reappeared: int | None = None) -> Takedown:  # fmt: skip
    return Takedown(project_id=rules.project, alert_id=alert_id, finding_id=finding_id, domain="x.example",
                    target={"kind": "registrar", "name": "Example"}, language="en", subject="s", body="b",
                    state=state, created_by=user_id, created_at=NOW, updated_at=NOW, resolved_at=resolved,
                    reappeared_alert_id=reappeared)  # fmt: skip


async def test_purge_cases_cascade(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    user = await security.create_user(
        session, username="alice", password="x" * 16, roles=["analyst"], now=NOW
    )
    old_low, _ = await _case(
        session, sbr_rules, "sbr-low.top", last_seen=NOW - timedelta(days=400), alert_status=None
    )
    young_low, _ = await _case(
        session, sbr_rules, "sbr-young.top", last_seen=NOW - timedelta(days=100), alert_status=None
    )
    case_f, case_a = await _case(
        session, sbr_rules, "sbr-case.top", last_seen=NOW - timedelta(days=1200)
    )
    assert case_a is not None
    other_f, other_a = await _case(
        session, sbr_rules, "sbr-other.top", last_seen=NOW, alert_status="open"
    )
    assert other_a is not None
    td = _takedown(
        sbr_rules, case_f, case_a, user.id, "removed", resolved=NOW - timedelta(days=1150)
    )
    session.add(td)
    await session.flush()
    session.add_all([
        TakedownEvent(takedown_id=td.id, ts=NOW - timedelta(days=1150), actor="system", from_state="submitted",
                      to_state="removed"),
        Evidence(finding_id=case_f, alert_id=case_a, kind="screenshot", object_key="evidence/aa/1.png", sha256="a" * 64,
                 size=3, content_type="image/png", captured_at=NOW, node_id="local", method="test", version_id="v1"),
        SuppressionRule(project_id=sbr_rules.project, kind="domain", value="sbr-case.top", source_alert_id=case_a,
                        created_at=NOW),
        Adjudication(finding_id=case_f, status="done", created_at=NOW, updated_at=NOW),
        # 另一案件的下架记录把本案件的告警记为"复活告警"：删除时只置空引用
        _takedown(sbr_rules, other_f, other_a, user.id, "reappeared", reappeared=case_a),
    ])  # fmt: skip
    await session.flush()
    result = await purge_findings(
        session, findings_before=NOW - timedelta(days=365), cases_before=NOW - timedelta(days=1095)
    )
    assert result.counts == {"findings": 2, "alerts": 1, "evidence": 1, "takedowns": 1}
    assert result.objects == [("evidence/aa/1.png", "v1")]
    remaining = set(await session.scalars(select(Finding.id)))
    assert remaining == {young_low, other_f} and old_low not in remaining
    rule = (await session.scalars(select(SuppressionRule))).one()
    assert rule.source_alert_id is None  # 抑制规则保留
    kept = (await session.scalars(select(Takedown))).one()
    assert kept.finding_id == other_f and kept.reappeared_alert_id is None
    assert await session.scalar(select(func.count()).select_from(Adjudication)) == 0


async def test_purge_keeps_active_cases(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    user = await security.create_user(
        session, username="bob", password="x" * 16, roles=["analyst"], now=NOW
    )
    ancient = NOW - timedelta(days=2000)
    await _case(session, sbr_rules, "sbr-open.top", last_seen=ancient, alert_status="open")
    await _case(session, sbr_rules, "sbr-ack.top", last_seen=ancient, alert_status="acknowledged")
    f1, a1 = await _case(session, sbr_rules, "sbr-td.top", last_seen=ancient)
    f2, a2 = await _case(session, sbr_rules, "sbr-recent.top", last_seen=ancient)
    assert a1 is not None and a2 is not None
    session.add_all([
        _takedown(sbr_rules, f1, a1, user.id, "submitted"),  # 进行中的下架
        _takedown(sbr_rules, f2, a2, user.id, "removed", resolved=NOW - timedelta(days=30)),  # 刚结束
    ])  # fmt: skip
    await session.flush()
    result = await purge_findings(
        session, findings_before=NOW - timedelta(days=365), cases_before=NOW - timedelta(days=1095)
    )
    assert (
        result.counts["findings"] == 0
        and await session.scalar(select(func.count()).select_from(Alert)) == 4
    )


async def test_purge_keeps_grouped_alert_with_recent_finding(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    old_id, alert_id = await _case(
        session, sbr_rules, "sbr-group-old.top", last_seen=NOW - timedelta(days=1200)
    )
    recent_id, _ = await _case(
        session, sbr_rules, "sbr-group-new.top", last_seen=NOW, alert_status=None
    )
    assert alert_id is not None
    session.add(AlertFinding(alert_id=alert_id, finding_id=recent_id))
    await session.flush()
    result = await purge_findings(
        session, findings_before=NOW - timedelta(days=365), cases_before=NOW - timedelta(days=1095)
    )
    assert result.counts["findings"] == 0
    assert await session.get(Finding, old_id) is not None
    assert await session.get(Alert, alert_id) is not None


async def test_apply_runs_reports_and_config(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    old = NOW - timedelta(days=200)
    session.add_all([
        ConnectorRun(connector_id="crtsh", started_at=old, ended_at=old, status="ok", items=1, errors=0, message=""),
        ConnectorRun(connector_id="crtsh", started_at=old, ended_at=None, status="running", items=0, errors=0, message=""),
        ConnectorRun(connector_id="crtsh", started_at=NOW, ended_at=NOW, status="ok", items=1, errors=0, message=""),
        Report(project_id=sbr_rules.project, kind="daily", period_start=NOW - timedelta(days=401),
               period_end=NOW - timedelta(days=400), created_at=NOW - timedelta(days=400), content={}, sent_sinks=[]),
    ])  # fmt: skip
    await session.flush()
    result = await apply(session, RetentionConfig(), now=NOW)
    assert result.counts["connector_runs"] == 1 and result.counts["reports"] == 1
    assert set(result.counts) >= {
        "report_contacts",
        "exposed_accounts",
        "documents",
        "findings",
        "alerts",
    }
    assert (
        load_retention_config(Path("config/retention.yaml")) == RetentionConfig()
    )  # 仓库配置即默认值
    with pytest.raises(ValidationError):
        RetentionConfig(findings_days=400, cases_days=300)
    with pytest.raises(ValidationError):
        RetentionConfig(raw_items_days=1)


async def test_purge_removes_campaign_membership(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    old_f, _ = await _case(session, sbr_rules, "sbr-gone.top", last_seen=NOW - timedelta(days=1200))
    kept_f, _ = await _case(session, sbr_rules, "sbr-kept.top", last_seen=NOW, alert_status="open")
    campaign = Campaign(
        project_id=sbr_rules.project, state="confirmed", signature="s" * 64,
        created_at=NOW, updated_at=NOW,
    )  # fmt: skip
    session.add(campaign)
    await session.flush()
    session.add_all([
        CampaignMember(campaign_id=campaign.id, finding_id=old_f, state="member", added_at=NOW),
        CampaignMember(campaign_id=campaign.id, finding_id=kept_f, state="member", added_at=NOW),
    ])  # fmt: skip
    await session.flush()
    result = await purge_findings(
        session, findings_before=NOW - timedelta(days=365), cases_before=NOW - timedelta(days=1095)
    )
    assert result.counts["findings"] == 1
    remaining = list(await session.scalars(select(CampaignMember.finding_id)))
    assert remaining == [kept_f]


async def test_stale_social_candidates_without_alerts_are_deleted(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    account = ProtectedAccount(
        project_id=sbr_rules.project,
        platform="bluesky",
        handle="sbrank.bsky.social",
        created_at=NOW,
        next_check_at=NOW,
    )
    session.add(account)
    await session.flush()
    entity = await repo.upsert_entity(session, "url", "https://bsky.app/profile/did:plc:bad", NOW)
    up = await repo.upsert_finding(
        session,
        project_id=sbr_rules.project,
        entity=entity,
        score=Score(70, Severity.HIGH, Category.IMPERSONATION_ACCOUNT, {"avatar": 40}),
        match={},
        source="social_accounts",
        now=NOW,
    )
    await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
    old, recent = NOW - timedelta(days=91), NOW - timedelta(days=89)

    def candidate(did: str, seen: datetime, finding_id: int | None) -> AccountCandidate:
        return AccountCandidate(
            protected_id=account.id,
            platform_account_id=did,
            handle=f"{did[8:]}.bsky.social",
            profile_url=f"https://bsky.app/profile/{did}",
            score=25,
            finding_id=finding_id,
            first_seen=seen,
            last_seen=seen,
        )

    session.add_all(
        [
            candidate("did:plc:stale", old, None),
            candidate("did:plc:fresh", recent, None),
            candidate("did:plc:bad", old, up.finding.id),  # 关联过告警，保留到案件保留期
        ]
    )
    await session.flush()
    result = await apply(session, RetentionConfig(), now=NOW)
    assert result.counts["account_candidates"] == 1
    left = set((await session.scalars(select(AccountCandidate.platform_account_id))).all())
    assert left == {"did:plc:fresh", "did:plc:bad"}
