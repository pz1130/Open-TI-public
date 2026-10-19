import dataclasses
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.exposure import breach_catalog, exposure_payload
from opti.db.models import Alert, ExposedAccount, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
LEAK = {"Name": "NewLeak", "Title": "New Leak 2026", "BreachDate": "2026-08-01", "AddedDate": "2026-10-01T00:00:00Z",
        "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}  # fmt: skip


def _item(
    rules: ProjectRules, accounts: list[str], sid: str = "1", source: str = "hibp"
) -> RawItem:
    domain = rules.domains.official[0]
    info = breach_catalog([LEAK])["NewLeak"]
    payload = exposure_payload(
        source=source, kind="breach", key=f"hibp:{domain}:NewLeak", domain=domain, info=info,
        title=info.title, affected=len(accounts), accounts=accounts,
    )  # fmt: skip
    return RawItem(connector_id=source, source_item_id=sid, fetched_at=NOW, url=None, payload=payload,
                   project_ids=(rules.project,))  # fmt: skip


async def test_exposure_creates_breach_finding_and_accounts(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    domain = sbr_rules.domains.official[0]
    accounts = [f"user{i}@{domain}" for i in range(12)]
    proc = Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW)
    result = await proc.process(session, _item(sbr_rules, accounts))
    assert len(result.alerts) == 1
    finding = await session.get(Finding, result.findings[0])
    assert (
        finding is not None
        and finding.category == "credential_exposure"
        and finding.severity == "high"
    )
    assert finding.match["exposure"]["affected"] == 12
    assert {r["reason"] for r in finding.match["reasons"]} == {
        "passwords_exposed",
        "recent_breach",
        "many_accounts",
    }
    rows = (
        await session.scalars(select(ExposedAccount).where(ExposedAccount.finding_id == finding.id))
    ).all()
    assert sorted(r.email for r in rows) == sorted(accounts) and all(
        r.pushed_at is None for r in rows
    )


async def test_accounts_never_leave_the_exposure_table(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    domain = sbr_rules.domains.official[0]
    proc = Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW)
    item = _item(sbr_rules, [f"secret.person@{domain}"])
    item.payload["exposure"]["context"] = {"note": f"secret.person@{domain}", "users": 2}
    item.payload["other"] = f"secret.person@{domain}"
    result = await proc.process(session, item)
    raw = (await session.scalars(select(RawItemRow))).one()
    finding = await session.get(Finding, result.findings[0])
    alert = (await session.scalars(select(Alert))).one()
    for blob in (raw.payload, finding.match if finding else {}, alert.routing):
        assert "secret.person" not in json.dumps(blob)
    assert (
        raw.payload["exposure"]["accounts"] == [] and raw.payload["exposure"]["accounts_count"] == 1
    )


async def test_later_items_add_accounts_and_keep_metadata(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    domain = sbr_rules.domains.official[0]
    proc = Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW)
    first = await proc.process(session, _item(sbr_rules, [f"a@{domain}", f"b@{domain}"], sid="1"))
    # 通知邮件路径：同一事件，没有账户明细
    notification = _item(sbr_rules, [], sid="2", source="hibp_notify")
    notification.payload["exposure"].update(
        {
            "data_classes": [],
            "breach_date": None,
            "verified": False,
            "title": "NewLeak",
        }
    )
    await proc.process(session, notification)
    after_notification = await session.get(Finding, first.findings[0])
    assert after_notification is not None
    assert after_notification.severity == "high"
    assert after_notification.match["exposure"]["data_classes"] == ["Email addresses", "Passwords"]
    await proc.process(
        session, _item(sbr_rules, [f"a@{domain}", f"b@{domain}", f"c@{domain}"], sid="3")
    )
    finding = await session.get(Finding, first.findings[0])
    assert finding is not None and finding.match["exposure"]["affected"] == 3  # 取已知的最大数
    assert set(finding.sources) == {"hibp", "hibp_notify"}
    emails = (
        await session.scalars(
            select(ExposedAccount.email).where(ExposedAccount.finding_id == finding.id)
        )
    ).all()
    assert sorted(emails) == [f"a@{domain}", f"b@{domain}", f"c@{domain}"]


async def test_invalid_payload_is_rejected(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    proc = Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW)
    item = _item(sbr_rules, [])
    bad = dataclasses.replace(
        item, payload={"exposure": {**item.payload["exposure"], "domain": "evil.org"}}
    )
    result = await proc.process(session, bad)
    assert result.findings == [] and result.alerts == []
