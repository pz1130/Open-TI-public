from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.leakposts import leak_post_payload
from opti.core.vendors import PartyMatcher, VendorList
from opti.db.models import Alert, Finding, LeakPost, RawItemRow
from opti.organization import Organization
from opti.pipeline import leakposts
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
HOSTS = ("ransomware.live", "www.ransomlook.io")
VENDORS = VendorList.model_validate(
    {
        "vendors": [
            {
                "id": "acme",
                "name": "Acme Holdings Ltd",
                "domains": ["acme.example"],
                "tier": "critical",
            }
        ]
    }
)


def _processor(rules: ProjectRules, vendors: VendorList = VENDORS) -> Processor:
    org = Organization(name="Example Development Bank", short_name="EDB")
    return Processor(rules, EnrichmentService({}), clock=lambda: NOW,
                     parties=PartyMatcher(org, rules.domains.official, vendors))  # fmt: skip


def _item(rules: ProjectRules, raw: dict[str, Any], source: str = "ransomware_live") -> RawItem:
    payload = leak_post_payload(raw, source=source, allow_hosts=HOSTS)
    assert payload is not None
    return RawItem(connector_id=source, source_item_id=payload["leak_post"]["key"], fetched_at=NOW, url=None,
                   payload=payload, project_ids=(rules.project,))  # fmt: skip


async def test_vendor_victim_alerts(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    raw = {
        "victim": "Acme Inc",
        "group": "akira",
        "discovered": "2026-10-02",
        "domain": "acme.example",
    }
    result = await _processor(sbr_rules).process(session, _item(sbr_rules, raw))
    [fid] = result.findings
    finding = await session.get(Finding, fid)
    assert (
        finding is not None
        and finding.category == "ransomware_mention"
        and finding.severity == "high"
    )
    assert (
        finding.match["post"]["group"] == "akira" and finding.match["post"]["victim"] == "Acme Inc"
    )
    [party] = finding.match["parties"]
    assert party["id"] == "acme" and party["how"] == "domain" and party["tier"] == "critical"
    assert {r["reason"] for r in finding.match["reasons"]} == {
        "critical_vendor",
        "matched_by_domain",
    }
    assert len(result.alerts) == 1


async def test_own_organization_is_critical(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    raw = {"victim": sbr_rules.domains.official[0], "group": "lockbit3", "discovered": "2026-10-03"}
    result = await _processor(sbr_rules).process(session, _item(sbr_rules, raw))
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.severity == "critical"


async def test_unmatched_posts_are_stored_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    result = await _processor(sbr_rules).process(
        session,
        _item(sbr_rules, {"victim": "Unrelated GmbH", "group": "play", "discovered": "2026-10-02"}),
    )
    assert result.findings == [] and result.alerts == []
    assert await session.scalar(select(func.count()).select_from(LeakPost)) == 1


async def test_same_post_from_two_sources_alerts_once(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    proc = _processor(sbr_rules)
    raw = {"victim": "Acme Inc", "group": "Akira", "discovered": "2026-10-02",
           "url": "https://ransomware.live/id/1"}  # fmt: skip
    first = await proc.process(session, _item(sbr_rules, raw))
    again = await proc.process(session, _item(sbr_rules, raw))  # 同一来源再次返回：被重放检查跳过
    second = await proc.process(
        session,
        _item(sbr_rules, {"post_title": "ACME, Inc.", "group_name": "akira", "discovered": "2026-10-01 23:00:00",
                          "link": "https://www.ransomlook.io/group/akira"}, source="ransomlook"),
    )  # fmt: skip
    assert len(first.alerts) == 1 and again.alerts == [] and second.alerts == []
    post = (await session.scalars(select(LeakPost))).one()
    assert post.sources == ["ransomlook", "ransomware_live"]
    assert post.discovered == datetime(2026, 10, 1, 23, tzinfo=UTC)  # 取最早的发现时间
    assert set(post.links) == {
        "https://ransomware.live/id/1",
        "https://www.ransomlook.io/group/akira",
    }
    finding = await session.get(Finding, first.findings[0])
    assert finding is not None and set(finding.sources) == {"ransomware_live", "ransomlook"}
    assert await session.scalar(select(func.count()).select_from(Alert)) == 1


async def test_no_parties_configured(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    proc = Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW)  # 未装配 PartyMatcher
    result = await proc.process(
        session,
        _item(sbr_rules, {"victim": "Acme Inc", "group": "akira", "discovered": "2026-10-02"}),
    )
    assert result.findings == []
    assert await session.scalar(select(func.count()).select_from(LeakPost)) == 1


async def test_old_post_is_low(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    old = (NOW - timedelta(days=300)).date().isoformat()
    vendors = VendorList.model_validate(
        {"vendors": [{"id": "n", "name": "Normal Vendor", "tier": "normal"}]}
    )
    result = await _processor(sbr_rules, vendors).process(
        session, _item(sbr_rules, {"victim": "Normal Vendor", "group": "akira", "discovered": old})
    )
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.severity == "low" and result.alerts == []


async def test_untrusted_post_fields_are_not_saved(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    item = _item(sbr_rules, {"victim": "Acme", "group": "akira", "discovered": "2026-10-02"})
    item.payload["leak_post"]["links"] = ["javascript:alert(1)", "https://ransomware.live/post"]
    item.payload["leak_post"]["secret"] = "do-not-store"
    await _processor(sbr_rules).process(session, item)
    stored = (await session.scalars(select(RawItemRow))).one()
    assert "secret" not in stored.payload["leak_post"]
    assert stored.payload["leak_post"]["links"] == ["https://ransomware.live/post"]


async def test_rematch_finds_new_vendor_once(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    empty = _processor(sbr_rules, VendorList())
    recent = (NOW - timedelta(days=10)).date().isoformat()
    ancient = (NOW - timedelta(days=400)).date().isoformat()
    await empty.process(
        session,
        _item(sbr_rules, {"victim": "Gamma Logistics Ltd", "group": "play", "discovered": recent}),
    )
    await empty.process(
        session,
        _item(sbr_rules, {"victim": "Gamma Logistics", "group": "akira", "discovered": ancient}),
    )
    assert await session.scalar(select(func.count()).select_from(Finding)) == 0
    # 名单新增供应商后补做比对：一年内的帖子产生告警，一年前的不再处理
    vendors = VendorList.model_validate(
        {"vendors": [{"id": "gamma", "name": "Gamma Logistics", "tier": "critical"}]}
    )
    updated = _processor(sbr_rules, vendors)
    [alert_id] = await leakposts.rematch(session, updated, now=NOW)
    alert = await session.get(Alert, alert_id)
    assert alert is not None and alert.severity == "high"  # 55 + 5 + 10（10 天前）
    assert await leakposts.rematch(session, updated, now=NOW) == []  # 再次运行不重复
    finding = (await session.scalars(select(Finding))).one()
    assert finding.sources == ["rematch"]
