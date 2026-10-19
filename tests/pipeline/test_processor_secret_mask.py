"""RED Team 4: platform intake masks credentials before persisting, whatever the collector did."""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


async def test_unmasked_paste_is_masked_at_rest(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    item = RawItem(
        connector_id="pastebin",
        source_item_id="paste-1",
        fetched_at=NOW,
        url=f"https://paste.example/raw/1?t={GH}",
        payload={
            "text": f"Example Development Bank prod\naws_key={AWS}\n",
            "nested": [{"doc": GH}],
        },
        project_ids=(sbr_rules.project,),
    )
    await Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW).process(session, item)
    rows = (await session.execute(select(RawItemRow))).scalars().all()
    assert rows
    dump = json.dumps(
        [{c.name: str(getattr(r, c.name)) for c in r.__table__.columns} for r in rows],
        ensure_ascii=False,
    )
    assert AWS not in dump and GH not in dump
    assert "AKIA…[REDACTED:" in dump
