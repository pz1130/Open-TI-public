from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api import security
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, Entity, Finding, FindingObservation, RawItemRow, WatchedDomain
from opti.pipeline import submissions
from opti.pipeline.submissions import Submission, SubmissionError
from opti.takedown import hosting
from opti.takedown.config import Platform, TakedownConfig

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 7, 8, tzinfo=UTC)
CFG = TakedownConfig(
    platforms=(
        Platform(id="linkedin", name="LinkedIn", hosts=("linkedin.com",)),
        Platform(id="telegram", name="Telegram", hosts=("t.me",)),
    )
)


async def _user(session: AsyncSession) -> int:
    user = await security.create_user(
        session,
        username="alice",
        password="correct horse battery staple",
        roles=["analyst"],
        now=NOW,
    )
    return user.id


def _sub(
    url: str,
    category: Category = Category.IMPERSONATION_ACCOUNT,
    severity: Severity = Severity.HIGH,
    **kw: Any,
) -> Submission:
    return Submission(
        url=url,
        category=category,
        severity=severity,
        description=kw.pop("description", "冒充高管发布虚假招聘"),
        **kw,
    )


async def _submit(
    session: AsyncSession, rules: ProjectRules, uid: int, sub: Submission
) -> submissions.SubmissionResult:
    return await submissions.submit(session, sub, rules=rules, cfg=CFG, user_id=uid, now=NOW)


async def test_platform_url_is_not_fetched_or_watched(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    r = await _submit(
        session,
        sbr_rules,
        uid,
        _sub(
            "https://www.LinkedIn.com/in/fake-sbr-ceo/?utm_source=x",
            category=Category.PHISHING_SITE,
        ),
    )
    alert, finding = await session.get(Alert, r.alert_id), await session.get(Finding, r.finding_id)
    assert alert is not None and finding is not None
    assert r.platform == "linkedin" and r.created_alert
    assert r.url == "https://www.linkedin.com/in/fake-sbr-ceo/"
    assert alert.evidence_status == "none" and alert.assignee_id == uid and alert.severity == "high"
    assert alert.routing["reasons"] == ["manual_submission"]
    assert finding.score == 75 and finding.score_breakdown == {"manual": 75}
    assert finding.match["platform"] == "linkedin"
    assert finding.match["manual"]["description"] == "冒充高管发布虚假招聘"
    assert (await session.scalars(select(WatchedDomain))).all() == []
    assert finding.entity_id not in await hosting.pending_entity_ids(session, NOW, limit=10)
    raw = await session.scalar(
        select(RawItemRow).where(RawItemRow.connector_id == "manual_submission")
    )
    assert raw is not None and raw.payload["manual"]["submitted_by"] == uid
    assert raw.payload["platform"] == "linkedin"


async def test_other_url_is_captured_and_watched(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    r = await _submit(
        session,
        sbr_rules,
        uid,
        _sub(
            "https://sbr-careers.top/apply", category=Category.FRAUD_SCAM, severity=Severity.MEDIUM
        ),
    )
    alert, finding = await session.get(Alert, r.alert_id), await session.get(Finding, r.finding_id)
    assert alert is not None and finding is not None
    assert r.platform is None and alert.evidence_status == "pending"
    assert alert.severity == "medium" and finding.category == "fraud_scam"
    assert (await session.scalars(select(WatchedDomain.domain))).all() == ["sbr-careers.top"]
    assert finding.entity_id in await hosting.pending_entity_ids(session, NOW, limit=10)


async def test_platform_resubmission_cancels_preexisting_capture(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    first = await _submit(session, sbr_rules, uid, _sub("https://www.linkedin.com/in/fake-ceo/"))
    alert = await session.get(Alert, first.alert_id)
    assert alert is not None
    alert.evidence_status = "pending"
    await session.flush()
    again = await _submit(session, sbr_rules, uid, _sub("https://www.linkedin.com/in/fake-ceo/"))
    assert again.alert_id == first.alert_id and not again.created_alert
    assert alert.evidence_status == "none"


async def test_other_url_resubmission_retries_failed_capture(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    first = await _submit(session, sbr_rules, uid, _sub("https://sbr-careers.top/apply"))
    alert = await session.get(Alert, first.alert_id)
    assert alert is not None
    alert.evidence_status = "failed"
    alert.evidence_attempts = 3
    await session.flush()
    again = await _submit(session, sbr_rules, uid, _sub("https://sbr-careers.top/apply"))
    assert again.alert_id == first.alert_id and not again.created_alert
    assert alert.evidence_status == "pending" and alert.evidence_attempts == 0


async def test_resubmission_merges_and_never_downgrades(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    url = "https://sbr-careers.top/apply"
    first = await _submit(session, sbr_rules, uid, _sub(url, severity=Severity.HIGH))
    again = await _submit(session, sbr_rules, uid, _sub(url, severity=Severity.MEDIUM))
    assert again.alert_id == first.alert_id and not again.created_alert
    finding = await session.get(Finding, first.finding_id)
    assert finding is not None and finding.severity == "high" and finding.score == 75
    count = await session.scalar(
        select(func.count())
        .select_from(FindingObservation)
        .where(FindingObservation.finding_id == first.finding_id)
    )
    assert count == 2
    higher = await _submit(session, sbr_rules, uid, _sub(url, severity=Severity.CRITICAL))
    assert higher.created_alert and higher.alert_id != first.alert_id
    old = await session.get(Alert, first.alert_id)
    assert old is not None and old.status == "superseded"


async def test_resubmission_after_close_opens_new_alert(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    url = "https://sbr-careers.top/apply"
    first = await _submit(session, sbr_rules, uid, _sub(url))
    alert = await session.get(Alert, first.alert_id)
    assert alert is not None
    alert.status = "closed"
    await session.flush()
    again = await _submit(session, sbr_rules, uid, _sub(url))
    assert again.created_alert and again.alert_id != first.alert_id


async def test_rejects_official_private_and_invalid(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    for url in (
        "https://www.sbr.int/careers",
        "https://sbrbank.com/",
        "http://10.0.0.5/login",
        "http://[::1]/",
        "ftp://sbr-x.top/",
        "not a url",
    ):
        with pytest.raises(SubmissionError):
            await _submit(session, sbr_rules, uid, _sub(url))
    with pytest.raises(SubmissionError):
        await _submit(session, sbr_rules, uid, _sub("https://sbr-x.top/", description="   "))
    with pytest.raises(SubmissionError):
        await _submit(
            session, sbr_rules, uid, _sub("https://sbr-x.top/", category=Category.BRAND_MENTION)
        )
    with pytest.raises(SubmissionError):
        await _submit(session, sbr_rules, uid, _sub("https://sbr-x.top/", severity=Severity.LOW))
    assert (await session.scalars(select(Finding))).all() == []


async def test_shared_host_is_not_watched(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    uid = await _user(session)
    # 共享主机（Google Sites、表单、短链接）不是仿冒域名：只截图取证，不把整个主机加入监视
    for url in (
        "https://sites.google.com/view/sbr-grants",
        "https://docs.google.com/forms/d/x/viewform",
    ):
        r = await _submit(session, sbr_rules, uid, _sub(url, category=Category.FRAUD_SCAM))
        alert = await session.get(Alert, r.alert_id)
        assert alert is not None and alert.evidence_status == "pending"
    assert (await session.scalars(select(WatchedDomain))).all() == []


async def test_resubmitting_platform_url_keeps_existing_evidence_status(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    first = await _submit(
        session, sbr_rules, uid, _sub("https://www.linkedin.com/in/fake-sbr-ceo/")
    )
    alert = await session.get(Alert, first.alert_id)
    assert alert is not None
    alert.evidence_status = "done"  # 例如已有上传截图或之前的取证
    await session.flush()
    again = await _submit(
        session, sbr_rules, uid, _sub("https://www.linkedin.com/in/fake-sbr-ceo/")
    )
    assert again.alert_id == first.alert_id and alert.evidence_status == "done"
    alert.evidence_status = "pending"  # 自动告警排队等沙箱：平台链接改为不取证
    await session.flush()
    await _submit(session, sbr_rules, uid, _sub("https://www.linkedin.com/in/fake-sbr-ceo/"))
    assert alert.evidence_status == "none"


async def test_automated_update_keeps_manual_details(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    uid = await _user(session)
    r = await _submit(
        session, sbr_rules, uid, _sub("https://t.me/fake_sbr", severity=Severity.CRITICAL)
    )
    finding = await session.get(Finding, r.finding_id)
    assert finding is not None
    entity = await session.get(Entity, finding.entity_id)
    assert entity is not None
    # 之后钓鱼情报源也报了同一 URL：自动流程整体重写匹配信息与分数
    await repo.upsert_finding(
        session, project_id=sbr_rules.project, entity=entity,
        score=Score(60, Severity.MEDIUM, Category.PHISHING_SITE, {"base": 40, "intel_hits": 20}),
        match={"url": "https://t.me/fake_sbr", "reasons": [{"reason": "intel"}]}, source="openphish", now=NOW,
    )  # fmt: skip
    assert finding.match["manual"]["description"] == "冒充高管发布虚假招聘"
    assert finding.match["platform"] == "telegram"
    assert finding.match["reasons"] == [{"reason": "intel"}]
    assert (finding.score, finding.severity) == (90, "critical")  # 不低于分析员选定的级别
    assert finding.category == "impersonation_account"  # 类别以分析员选定的为准


def test_manual_source_name_is_shared() -> None:
    assert hosting.MANUAL_SOURCE == submissions.CONNECTOR_ID
