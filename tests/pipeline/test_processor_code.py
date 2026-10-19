import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.adjudication import LlmConfig
from opti.core.config import ProjectRules
from opti.db.models import Adjudication, Alert, CodeRepo, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.llm_runtime import StaticLlm
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)


def _hit(rules: ProjectRules, path: str, *, kind: str = "domain", repo: str = "Dev2/Deploy",
         sha: str = "s1") -> RawItem:  # fmt: skip
    hit = {"repo": repo, "path": path, "html_url": f"https://github.com/{repo}/blob/main/{path}",
           "blob_sha": sha, "term": "intranet-gw01" if kind == "internal" else rules.domains.official[0],
           "term_kind": kind, "fork": False, "fragments": ["HOST=intranet-gw01"]}  # fmt: skip
    return RawItem(connector_id="github_code", source_item_id=f"{repo}:{path}:{sha}", fetched_at=NOW,
                   url=hit["html_url"], payload={"code_hit": hit}, project_ids=(rules.project,))  # fmt: skip


def _scan(*secrets: dict[str, Any]) -> dict[str, Any]:
    return {"supported": True, "scanned": True, "commit": "a" * 40,
            "depth": 100, "total": len(secrets), "secrets": list(secrets)}  # fmt: skip


SECRET = {"rule": "aws-access-token", "description": "AWS", "file": "config/app.env", "line": 2,
          "commit": "c" * 40, "date": "2026-09-20T00:00:00Z", "prefix": "AKIA", "fingerprint": "f" * 64,
          "length": 20, "url": "https://github.com/dev2/deploy/blob/ccc/config/app.env#L2"}  # fmt: skip


CODE_ON = StaticLlm(LlmConfig(code_enabled=True))


def _processor(rules: ProjectRules, llm: StaticLlm | None = None) -> Processor:
    return Processor(rules, EnrichmentService({}), clock=lambda: NOW, llm=llm)


async def test_readme_mention_is_info(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    result = await _processor(sbr_rules).process(session, _hit(sbr_rules, "README.md"))
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "data_leak" and finding.severity == "info"
    assert result.alerts == []
    assert finding.match["repo"] == "dev2/deploy" and len(finding.match["hits"]) == 1
    assert (
        finding.match["disclosure"]["report"]
        == "https://github.com/dev2/deploy/security/advisories/new"
    )
    row = (await session.scalars(select(CodeRepo))).one()
    assert row.repo == "dev2/deploy" and row.scan_status == "pending" and row.next_scan_at == NOW


async def test_internal_config_alerts_and_hits_merge(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    result = await processor.process(session, _hit(sbr_rules, "config/app.env", kind="internal"))
    assert len(result.alerts) == 1
    await processor.process(session, _hit(sbr_rules, "config/app.env", kind="internal", sha="s2"))
    finding = (await session.scalars(select(Finding))).one()
    assert len(finding.match["hits"]) == 1 and finding.severity == "medium"


async def test_scan_with_secret_in_hit_file_is_critical(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    [alert_id] = await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    finding = (await session.scalars(select(Finding))).one()
    assert finding.category == "secret_leak" and finding.severity == "critical"
    assert finding.match["scan"]["secrets"][0]["prefix"] == "AKIA"
    assert finding.match["scan"]["scanned_at"] == NOW.isoformat()
    assert {reason["reason"] for reason in finding.match["reasons"]} == {
        "secret_critical",
        "secret_in_brand_file",
    }
    alert = await session.get(Alert, alert_id)
    assert alert is not None and alert.severity == "critical"


async def test_rescan_without_secrets_downgrades(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    assert (
        await processor.on_repo_scanned(session, "dev2/deploy", _scan(), NOW + timedelta(days=30))
        == []
    )
    finding = (await session.scalars(select(Finding))).one()
    assert finding.category == "data_leak" and finding.severity == "low"


async def test_failed_scan_keeps_last_result(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    failed = {"supported": True, "scanned": False, "error": "clone_timeout"}
    assert (
        await processor.on_repo_scanned(session, "dev2/deploy", failed, NOW + timedelta(days=31))
        == []
    )
    finding = (await session.scalars(select(Finding))).one()
    assert (
        finding.category == "secret_leak" and finding.match["scan"]["scanned_at"] == NOW.isoformat()
    )


async def test_skipped_scan_keeps_last_result(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    skipped = {"supported": True, "scanned": False, "skipped": "private"}
    assert (
        await processor.on_repo_scanned(session, "dev2/deploy", skipped, NOW + timedelta(days=31))
        == []
    )
    finding = (await session.scalars(select(Finding))).one()
    assert finding.category == "secret_leak"
    assert finding.match["scan"]["scanned_at"] == NOW.isoformat()


async def test_invalid_or_untrusted_hit_not_saved(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    item = _hit(sbr_rules, "x.cfg")
    bad = dataclasses.replace(
        item,
        payload={
            "code_hit": {
                **item.payload["code_hit"],
                "html_url": "https://evil.example/x",
                "Secret": "do-not-store",
            }
        },
    )
    assert (await _processor(sbr_rules).process(session, bad)).findings == []
    stored = (await session.scalars(select(RawItemRow))).one()
    assert stored.payload == {"code_hit": {"invalid": True}}


async def _verdict(session: AsyncSession, verdict: str, relation: str) -> Finding:
    """模拟研判已完成：结论落在当前密钥指纹上，排队请求已处理。"""
    finding = (await session.scalars(select(Finding))).one()
    finding.match = {**finding.match, "llm_code": {
        "secrets": [{"fingerprint": s["fingerprint"], "verdict": verdict} for s in finding.match["scan"]["secrets"]],
        "relation": relation, "confidence": 0.8, "rationale": "r", "summary": "s",
        "model": "fake-1", "prompt_version": "code-1", "assessed_at": NOW.isoformat()}}  # fmt: skip
    for row in (await session.scalars(select(Adjudication))).all():
        row.status = "done"
    await session.flush()
    return finding


async def test_code_adjudication_holds_secret_alert(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules, CODE_ON)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    assert await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW) == []
    row = (await session.scalars(select(Adjudication))).one()
    assert row.status == "pending" and row.held_severity == "critical"
    assert (await session.scalars(select(Alert))).all() == []


async def test_code_switch_off_alerts_by_rules(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules, StaticLlm(LlmConfig()))
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    [alert_id] = await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    assert (await session.scalars(select(Adjudication))).all() == []
    assert (await session.get(Alert, alert_id)) is not None


async def test_verdict_is_reused_while_secrets_unchanged(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules, CODE_ON)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    await _verdict(session, "example", "unrelated")
    later = NOW + timedelta(days=30)
    assert await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), later) == []
    finding = (await session.scalars(select(Finding))).one()
    assert finding.score == 75 and finding.severity == "high"  # 规则 100，示例 -15，无关 -10
    assert (
        finding.score_breakdown["llm_secret"] == -15
        and finding.match["llm_code"]["relation"] == "unrelated"
    )
    await processor.process(session, _hit(sbr_rules, "README.md", sha="s2"))  # 只新增品牌命中
    assert len((await session.scalars(select(Adjudication))).all()) == 1
    finding = (await session.scalars(select(Finding))).one()
    assert finding.score == 75 and len(finding.match["hits"]) == 2


async def test_new_secret_is_adjudicated_again(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules, CODE_ON)
    await processor.process(session, _hit(sbr_rules, "config/app.env"))
    await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET), NOW)
    await _verdict(session, "real", "org")
    other = {**SECRET, "file": "deploy/prod.env", "fingerprint": "e" * 64}
    later = NOW + timedelta(days=30)
    await processor.on_repo_scanned(session, "dev2/deploy", _scan(SECRET, other), later)
    rows = (await session.scalars(select(Adjudication).order_by(Adjudication.id))).all()
    assert [r.status for r in rows] == ["done", "pending"]
    finding = (await session.scalars(select(Finding))).one()
    assert "llm_code" not in finding.match and "llm_secret" not in finding.score_breakdown
