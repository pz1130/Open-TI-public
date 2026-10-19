from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.evaluation import SetResult, run_golden
from opti.core.scoring import Category, Score, Severity
from opti.core.watcher import Comparison
from opti.db import repo
from opti.db.models import AlertFinding, Entity, Evidence
from opti.pipeline import acceptance

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 4, 8, tzinfo=UTC)
GOLDEN = Path(__file__).resolve().parents[2] / "eval" / "golden"


async def _alert(session: AsyncSession, rules: ProjectRules, value: str, severity: Severity,
                 verdict: str | None = None) -> tuple[int, int]:  # fmt: skip
    await repo.upsert_project(session, rules)
    entity = await repo.upsert_entity(session, "domain", value, NOW - timedelta(days=1))
    score = Score(70, severity, Category.TYPOSQUAT_DOMAIN, {"base": 70})
    up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=score, match={},
                                   source="certstream", now=NOW - timedelta(days=1))  # fmt: skip
    alert = await repo.open_alert(session, up.finding, severity, NOW - timedelta(days=1))
    alert.triage_verdict = verdict
    return alert.id, entity.id


def _connector(
    cid: str, tier: str, runnable: bool | None = True, kind: str = "poll"
) -> dict[str, Any]:
    return {"id": cid, "tier": tier, "kind": [kind], "runnable": runnable}


async def test_run_checks(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    for i in range(12):
        verdict = "true_positive" if i < 8 else "false_positive"
        await _alert(session, sbr_rules, f"sbr-m{i}.top", Severity.MEDIUM, verdict)
    complete, entity_id = await _alert(session, sbr_rules, "sbr-full.top", Severity.HIGH)
    await _alert(session, sbr_rules, "sbr-bare.top", Severity.HIGH)  # 没有截图与富化：不完整
    entity = await session.get(Entity, entity_id)
    assert entity is not None
    entity.enrichment = {
        "rdap": {"data": {}, "fetched_at": "x"},
        "dns": {"data": {}, "fetched_at": "x"},
    }
    finding_id = (
        await session.scalars(
            select(AlertFinding.finding_id).where(AlertFinding.alert_id == complete)
        )
    ).one()
    session.add(Evidence(finding_id=finding_id, alert_id=complete, kind="screenshot", object_key="k", sha256="a" * 64,
                         size=1, content_type="image/png", captured_at=NOW, node_id="local", method="test"))  # fmt: skip
    await session.flush()
    catalog = [_connector(f"free{i}", "free") for i in range(16)] + [
        _connector("paid1", "paid"), _connector("fm", "freemium"), _connector("off", "free", runnable=False),
        _connector("enr", "free", kind="enricher"), _connector("hk", "free", runnable=None),
    ]  # fmt: skip
    missed = Comparison(both=["sbr-loans.com"], ours_only=[],
                        watcher_only=[{"domain": "sbr-x.top", "status": "not_found"}])  # fmt: skip
    golden = run_golden(sbr_rules, GOLDEN)
    checks = {c.key: c for c in await acceptance.run(session, rules=sbr_rules, catalog=catalog, golden=golden,
                                                      watcher=missed, now=NOW, days=30)}  # fmt: skip
    assert list(checks) == ["mttd_ct", "mttd_nrd", "precision", "recall", "mttr", "free_sources", "evidence",
                            "availability", "zero_paid", "golden", "watcher"]  # fmt: skip
    assert checks["mttd_ct"].status == "insufficient" and checks["mttr"].status == "insufficient"
    assert checks["precision"].status == "pass" and checks["precision"].value == "66.7%（8 / 12）"
    assert checks["recall"].status == "pass" and checks["golden"].status == "pass"
    assert checks["free_sources"].status == "pass" and checks["free_sources"].value == "16"
    assert "hk" in checks["free_sources"].note  # 等待采集节点上报的不计入
    assert (
        checks["zero_paid"].status == "fail"
        and "paid1" in checks["zero_paid"].note
        and "fm" in checks["zero_paid"].note
    )
    assert checks["evidence"].status == "fail" and checks["evidence"].value == "50.0%（1 / 2）"
    assert checks["availability"].status == "manual" and checks["watcher"].status == "manual"
    assert "sbr-x.top" in checks["watcher"].note


async def test_url_host_evidence_requires_matching_target(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    entity = await repo.upsert_entity(session, "url", "https://sites.google.com/view/sbr-test", NOW)
    score = Score(80, Severity.HIGH, Category.PHISHING_SITE, {"base": 80})
    finding = await repo.upsert_finding(
        session, project_id=sbr_rules.project, entity=entity, score=score,
        match={}, source="phishing_db", now=NOW,
    )  # fmt: skip
    alert = await repo.open_alert(session, finding.finding, Severity.HIGH, NOW)
    entity.enrichment = {
        key: {"target_type": "domain", "target_value": "sites.google.com", "data": {}}
        for key in ("rdap", "dns")
    }
    session.add(Evidence(
        finding_id=finding.finding.id, alert_id=alert.id, kind="screenshot",
        object_key="url-shot", sha256="a" * 64, size=1, content_type="image/png",
        captured_at=NOW, node_id="local", method="test",
    ))  # fmt: skip
    await session.flush()
    check = await acceptance.evidence_check(session, sbr_rules.project, NOW - timedelta(days=30))
    assert check.status == "pass" and check.value == "100.0%（1 / 1）"
    entity.enrichment = {
        **entity.enrichment,
        "rdap": {"target_type": "domain", "target_value": "other.example", "data": {}},
    }
    await session.flush()
    check = await acceptance.evidence_check(session, sbr_rules.project, NOW - timedelta(days=30))
    assert check.status == "fail" and check.value == "0.0%（0 / 1）"


def test_render() -> None:
    checks = [
        acceptance.Check("precision", "告警精确率", "≥ 50%", "66.7%（8 / 12）", "pass"),
        acceptance.Check(
            "zero_paid", "默认连接器零付费", "无付费", "1 个付费", "fail", note="paid|1"
        ),
    ]
    md = acceptance.render_markdown(checks, project="demo", now=NOW, days=30)
    assert "| 告警精确率 | ≥ 50% | 66.7%（8 / 12） | 达标 |  |" in md and "paid\\|1" in md
    assert "达标 1 项、未达标 1 项" in md
    data = acceptance.to_json(checks, project="demo", now=NOW, days=30)
    assert data["overall"] == "fail" and data["checks"][0]["key"] == "precision"
    assert acceptance.to_json(checks[:1], project="demo", now=NOW, days=30)["overall"] == "pass"


def test_golden_and_watcher_checks() -> None:
    bad = [SetResult("domains", 10, 5, 3, 0, 0.7, 0.0), SetResult("urls", 1, 1, 1, 0, 0.7, 0.0)]
    recall, golden = acceptance.golden_checks(bad)
    assert recall.status == "fail" and recall.value == "50.0%" and golden.status == "fail"
    assert acceptance.watcher_check(None).status == "manual"
    clean = Comparison(
        both=["a.top"],
        ours_only=["b.top"],
        watcher_only=[{"domain": "sbr.int", "status": "protected"}],
    )
    assert acceptance.watcher_check(clean).status == "pass"


def test_missing_acceptance_evidence_stays_open() -> None:
    free, paid = acceptance.source_checks(
        [_connector(f"f{i}", "free") for i in range(14)]
        + [_connector("waiting", "free", runnable=None), _connector("quota", "freemium")]
    )
    assert free.status == "insufficient"
    assert paid.status == "manual"
    recall, golden = acceptance.golden_checks([])
    assert recall.status == "insufficient" and golden.status == "insufficient"
    assert acceptance.watcher_check(Comparison([], [], [])).status == "insufficient"
    checks = [free, paid]
    assert acceptance.to_json(checks, project="demo", now=NOW, days=30)["overall"] == "manual"


async def test_platform_alert_with_uploaded_screenshot_is_complete(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    url = "https://www.linkedin.com/in/fake-sbr-ceo/"
    entity = await repo.upsert_entity(session, "url", url, NOW - timedelta(days=1))
    up = await repo.upsert_finding(
        session, project_id=sbr_rules.project, entity=entity,
        score=Score(75, Severity.HIGH, Category.IMPERSONATION_ACCOUNT, {"manual": 75}),
        match={"url": url, "platform": "linkedin"}, source="manual_submission", now=NOW - timedelta(days=1),
    )  # fmt: skip
    alert = await repo.open_alert(session, up.finding, Severity.HIGH, NOW - timedelta(days=1))
    session.add(Evidence(finding_id=up.finding.id, alert_id=alert.id, kind="upload", object_key="k", sha256="a" * 64,
                         size=1, content_type="image/png", captured_at=NOW, node_id="upload", method="analyst-upload"))  # fmt: skip
    await session.flush()
    # 平台链接只能靠上传截图，也不查平台域名的 RDAP/DNS：上传截图即视为证据完整
    check = await acceptance.evidence_check(session, sbr_rules.project, NOW - timedelta(days=30))
    assert check.value == "100.0%（1 / 1）" and check.status == "pass"


async def test_escalated_platform_alert_counts_earlier_upload(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    url = "https://www.linkedin.com/in/fake-sbr-ceo/"
    entity = await repo.upsert_entity(session, "url", url, NOW - timedelta(days=1))
    up = await repo.upsert_finding(
        session, project_id=sbr_rules.project, entity=entity,
        score=Score(75, Severity.HIGH, Category.IMPERSONATION_ACCOUNT, {"manual": 75}),
        match={"url": url, "platform": "linkedin"}, source="manual_submission", now=NOW - timedelta(days=1),
    )  # fmt: skip
    old = await repo.open_alert(session, up.finding, Severity.HIGH, NOW - timedelta(days=1))
    session.add(Evidence(finding_id=up.finding.id, alert_id=old.id, kind="upload", object_key="k", sha256="a" * 64,
                         size=1, content_type="image/png", captured_at=NOW, node_id="upload", method="analyst-upload"))  # fmt: skip
    await repo.open_alert(session, up.finding, Severity.CRITICAL, NOW)  # 再次提交升级，旧告警被取代
    await session.flush()
    # 平台链接没有沙箱截图：升级后的新告警以同一链接此前上传的截图为证据
    check = await acceptance.evidence_check(session, sbr_rules.project, NOW - timedelta(days=30))
    assert check.value == "100.0%（2 / 2）" and check.status == "pass"
