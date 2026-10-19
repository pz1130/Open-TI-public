from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.pipeline import keyword_hits

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)


def _reasons(*pairs: tuple[str, str]) -> dict[str, Any]:
    return {"reasons": [{"reason": r, "token": t, "where": "registered"} for r, t in pairs]}


async def _finding(
    session: AsyncSession,
    rules: ProjectRules,
    domain: str,
    match: dict[str, Any],
    *,
    at: datetime = NOW,
    entity_type: str = "domain",
    alert: bool = False,
    project: str | None = None,
) -> int:
    entity = await repo.upsert_entity(session, entity_type, domain, at)
    score = Score(60, Severity.MEDIUM, Category.TYPOSQUAT_DOMAIN, {"base": 60})
    up = await repo.upsert_finding(
        session, project_id=project or rules.project, entity=entity, score=score,
        match=match, source="certstream", now=at,
    )  # fmt: skip
    if alert:
        await repo.open_alert(session, up.finding, Severity.MEDIUM, at)
    return up.finding.id


async def test_stats_counts_primary_reasons_per_token(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    await _finding(session, sbr_rules, "sbr-loans.com", _reasons(("brand_label", "sbr")))
    await _finding(
        session, sbr_rules, "sbr-pay.top",
        _reasons(("brand_label", "sbr"), ("fraud_affix", "pay")),
        at=NOW - timedelta(days=2),
    )  # fmt: skip
    await _finding(session, sbr_rules, "orbitfund.org", _reasons(("brand_combo", "orbit")))
    # 辅助原因、窗口外、非域名实体、其他项目都不算
    await _finding(session, sbr_rules, "loan-x.com", _reasons(("fraud_affix", "sbr")))
    await _finding(
        session, sbr_rules, "sbr-old.com", _reasons(("brand_label", "sbr")),
        at=NOW - timedelta(days=31),
    )  # fmt: skip
    await _finding(
        session, sbr_rules, "https://sbr-x.com/a", _reasons(("brand_label", "sbr")),
        entity_type="url",
    )  # fmt: skip
    await _finding(session, sbr_rules, "sbr-feed.com", {"reasons": "not-a-list"})
    other = sbr_rules.model_copy(update={"project": "other"})
    await repo.upsert_project(session, other)
    await _finding(
        session, sbr_rules, "sbr-other.com", _reasons(("brand_label", "sbr")), project="other"
    )

    out = await keyword_hits.stats(session, sbr_rules.project, ["sbr", "orbit", "zzz"], now=NOW)
    assert out == {
        "sbr": keyword_hits.TokenStat(2, NOW),
        "orbit": keyword_hits.TokenStat(1, NOW),
    }
    assert await keyword_hits.stats(session, sbr_rules.project, [], now=NOW) == {}


async def test_hits_lists_domains_with_latest_alert_and_pages(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    a = await _finding(
        session, sbr_rules, "sbr-a.com", _reasons(("brand_label", "sbr")),
        at=NOW - timedelta(hours=2), alert=True,
    )  # fmt: skip
    b = await _finding(
        session, sbr_rules, "sbr-b.com",
        _reasons(("brand_label", "sbr"), ("brand_substring", "sbr")),
        at=NOW - timedelta(hours=1),
    )  # fmt: skip
    await _finding(session, sbr_rules, "orbit-pay.com", _reasons(("brand_combo", "orbit")))

    first, total = await keyword_hits.hits(
        session, sbr_rules.project, "sbr", now=NOW, limit=1, offset=0
    )
    assert total == 2
    assert [(h.finding_id, h.domain, h.alert_id) for h in first] == [(b, "sbr-b.com", None)]
    second, _ = await keyword_hits.hits(
        session, sbr_rules.project, "sbr", now=NOW, limit=1, offset=1
    )
    assert second[0].finding_id == a
    assert second[0].alert_id is not None and second[0].alert_status == "open"
    assert second[0].severity == "medium" and second[0].score == 60


async def test_official_domain_counts_embedded_forms(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    match = _reasons(("official_embedded", "sbr.int"), ("brand_label", "sbr"))
    await _finding(session, sbr_rules, "sbr-int.com", match)
    out = await keyword_hits.stats(session, sbr_rules.project, ["sbr.int", "sbr"], now=NOW)
    assert out["sbr.int"].findings == 1 and out["sbr"].findings == 1


async def test_hyphenated_tokens_use_the_real_matcher_identity(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    from opti.core.domain_match import DomainMatcher
    from opti.pipeline.domain_keywords import add

    rules = add(sbr_rules, "brand", "sbr-fund")
    rules = add(rules, "restricted", "silk-road", ["loan"])
    await repo.upsert_project(session, rules)
    for domain in ("sbrfund-pay.top", "silkroadloan.top"):
        match = DomainMatcher(rules.domains).match(domain)
        assert match is not None and match.status == "match"
        await _finding(session, rules, domain, match.to_dict())
    counts = await keyword_hits.stats(session, rules.project, ["sbr-fund", "silk-road"], now=NOW)
    assert counts["sbr-fund"].findings == 1 and counts["silk-road"].findings == 1
    rows, total = await keyword_hits.hits(
        session, rules.project, "sbr-fund", now=NOW, limit=20, offset=0
    )
    assert total == 1 and rows[0].domain == "sbrfund-pay.top"
