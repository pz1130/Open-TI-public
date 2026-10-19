from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.kev import SoftwareList, SoftwareMatcher, digest, kev_payload
from opti.db.models import Alert, Entity, Finding, KevEntry
from opti.pipeline import kev
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
INVENTORY = SoftwareList.model_validate(
    {
        "software": [
            {
                "id": "vpn",
                "vendor": "Example Networks",
                "products": ["EdgeGate VPN"],
                "tier": "high",
                "owner": "网络组",
            }
        ]
    }
)


def _processor(rules: ProjectRules, inventory: SoftwareList = INVENTORY) -> Processor:
    return Processor(
        rules, EnrichmentService({}), clock=lambda: NOW, software=SoftwareMatcher(inventory)
    )


def _item(rules: ProjectRules, cve: str = "CVE-2026-12345", **change: Any) -> RawItem:
    raw = {"cveID": cve, "vendorProject": "Example Networks", "product": "EdgeGate VPN",
           "vulnerabilityName": "EdgeGate VPN Authentication Bypass", "dateAdded": "2026-09-28",
           "shortDescription": "Bypass.", "requiredAction": "Apply updates.", "dueDate": "2026-10-19",
           "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": ["CWE-287"], **change}  # fmt: skip
    payload = kev_payload(raw)
    assert payload is not None
    return RawItem(connector_id="cisa_kev", source_item_id=f"{cve}#{digest(payload)}", fetched_at=NOW, url=None,
                   payload=payload, project_ids=(rules.project,))  # fmt: skip


async def test_matched_kev_alerts(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    result = await _processor(sbr_rules).process(session, _item(sbr_rules))
    [fid] = result.findings
    f = await session.get(Finding, fid)
    assert (
        f is not None and f.category == "vulnerability" and f.severity == "medium" and f.score == 55
    )
    assert f.match["kev"]["cve"] == "CVE-2026-12345" and f.match["kev"]["due_date"] == "2026-10-19"
    assert f.match["software"] == [{"id": "vpn", "vendor": "Example Networks", "products": ["EdgeGate VPN"],
                                    "tier": "high", "exposed": False, "owner": "网络组"}]  # fmt: skip
    assert [r["reason"] for r in f.match["reasons"]] == ["high_software", "recently_added"]
    entity = await session.get(Entity, f.entity_id)
    assert entity is not None and (entity.type, entity.value) == ("cve", "CVE-2026-12345")
    assert len(result.alerts) == 1


async def test_ransomware_update_escalates(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    p = _processor(sbr_rules)
    first = await p.process(session, _item(sbr_rules))
    second = await p.process(session, _item(sbr_rules, knownRansomwareCampaignUse="Known"))
    assert (
        first.findings == second.findings and len(second.alerts) == 1
    )  # 55 → 65：Medium 升到 High
    f = await session.get(Finding, second.findings[0])
    assert (
        f is not None
        and f.severity == "high"
        and "ransomware_use" in [r["reason"] for r in f.match["reasons"]]
    )
    row = (await session.scalars(select(KevEntry))).one()
    assert row.ransomware is True and row.first_seen == NOW


async def test_unmatched_and_old_entries(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    p = _processor(sbr_rules)
    other = await p.process(session, _item(sbr_rules, "CVE-2026-11111", vendorProject="Other Corp"))
    assert other.findings == [] and other.alerts == []
    old = await p.process(session, _item(sbr_rules, "CVE-2023-22222", dateAdded="2023-01-10"))
    f = await session.get(Finding, old.findings[0])
    assert f is not None and f.severity == "low" and old.alerts == []  # 35 + 10 − 15 = 30
    assert (
        await session.scalar(select(func.count()).select_from(KevEntry)) == 2
    )  # 不匹配的也入库，供补比对
    bad = RawItem(connector_id="cisa_kev", source_item_id="x", fetched_at=NOW, url=None,
                  payload={"kev": {"cve": "nope"}}, project_ids=(sbr_rules.project,))  # fmt: skip
    assert (await p.process(session, bad)).findings == []
    assert await kev.products(session, vendor="example networks") == [
        ("Example Networks", "EdgeGate VPN", 1)
    ]
    assert [v for v, _, _ in await kev.products(session)] == ["Example Networks", "Other Corp"]


async def test_rematch_alerts_once(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _processor(sbr_rules, SoftwareList()).process(session, _item(sbr_rules))
    assert await session.scalar(select(func.count()).select_from(Finding)) == 0
    p = _processor(sbr_rules)  # 清单新增软件后补比对
    [alert_id] = await kev.rematch(session, p, now=NOW)
    alert = await session.get(Alert, alert_id)
    assert alert is not None and alert.severity == "medium"
    assert await kev.rematch(session, p, now=NOW) == []  # 再次运行不重复
    assert (await session.scalars(select(Finding))).one().sources == ["rematch"]
