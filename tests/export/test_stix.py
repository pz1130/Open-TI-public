from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity, severity_for
from opti.db import repo
from opti.db.models import Evidence, FindingObservation
from opti.export import stix as stix_export

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, tzinfo=UTC)


async def _finding(session: AsyncSession, rules: ProjectRules, etype: str, value: str, category: str, score: int,
                   *, when: datetime = NOW - timedelta(days=1), verdict: str | None = None) -> int:  # fmt: skip
    await repo.upsert_project(session, rules)
    entity = await repo.upsert_entity(session, etype, value, when)
    s = Score(score, severity_for(score), Category(category), {"base": score})
    up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=s,
                                   match={"reasons": [{"reason": "brand_label"}]}, source="test", now=when)  # fmt: skip
    if score >= 40:
        alert = await repo.open_alert(session, up.finding, s.severity, when)
        alert.triage_verdict = verdict
    return up.finding.id


async def test_collect_excludes_protected_and_dismissed(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    keep = await _finding(
        session,
        sbr_rules,
        "domain",
        "sbr-loans.com",
        "typosquat_domain",
        70,
        verdict="true_positive",
    )
    url = await _finding(session, sbr_rules, "url", "https://evil.example/sbr", "phishing_site", 80)
    await _finding(
        session, sbr_rules, "domain", "portal.sbr.int", "unapproved_certificate", 70
    )  # 官方域名的子域
    await _finding(
        session, sbr_rules, "domain", "sbrbank.com", "typosquat_domain", 70
    )  # 已知合法相似方
    await _finding(
        session, sbr_rules, "domain", "sbr-fp.top", "typosquat_domain", 70, verdict="false_positive"
    )
    low = await _finding(session, sbr_rules, "domain", "sbr-low.top", "typosquat_domain", 25)
    await _finding(
        session,
        sbr_rules,
        "domain",
        "sbr-old.top",
        "typosquat_domain",
        70,
        when=NOW - timedelta(days=40),
    )
    session.add(
        FindingObservation(
            finding_id=keep, item_id="ct:1", connector_id="certstream", observed_at=NOW, score=70
        )
    )
    session.add(Evidence(finding_id=keep, alert_id=None, kind="screenshot", object_key="k", sha256="b" * 64, size=10,
                         content_type="image/png", captured_at=NOW, node_id="local", method="test", source_url=None))  # fmt: skip
    await session.flush()
    since = NOW - timedelta(days=30)
    found = await stix_export.collect(session, sbr_rules, since=since, min_severity=Severity.MEDIUM)
    assert sorted(f.finding_id for f in found) == sorted([keep, url])
    k = next(f for f in found if f.finding_id == keep)
    assert (
        k.confirmed
        and k.observations == 1
        and k.evidence[0].sha256 == "b" * 64
        and k.entity_type == "domain"
    )
    assert not next(f for f in found if f.finding_id == url).confirmed
    with_low = await stix_export.collect(session, sbr_rules, since=since, min_severity=Severity.LOW)
    assert low in {f.finding_id for f in with_low} and len(with_low) == 3
    assert (
        len(
            await stix_export.collect(
                session, sbr_rules, since=since, min_severity=Severity.LOW, limit=1
            )
        )
        == 1
    )


async def test_collect_excludes_own_certificate_expiry(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    keep = await _finding(session, sbr_rules, "domain", "sbr-loans.com", "typosquat_domain", 70)
    await _finding(
        session, sbr_rules, "tls_endpoint", "www.example.com@3", "certificate_expiry", 90
    )  # 自有证书到期是内部运维问题，不是可共享的威胁情报
    found = await stix_export.collect(
        session, sbr_rules, since=NOW - timedelta(days=30), min_severity=Severity.MEDIUM
    )
    assert [f.finding_id for f in found] == [keep]
