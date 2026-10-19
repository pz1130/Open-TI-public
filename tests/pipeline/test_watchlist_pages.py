import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db import repo
from opti.db.models import Evidence, Finding
from opti.pipeline import watchlist
from opti.pipeline.enrichment import EnrichmentService
from opti.sdk.testing import make_context, static_enricher
from opti.storage.artifacts import store_saver
from opti.storage.objects import MemoryObjectStore

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 14, tzinfo=UTC)
DNS = {"exists": True, "a": ["8.8.8.8"]}


async def test_browser_parking_overrides_probe_and_saves_evidence_without_finding(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    await watchlist.ensure_watched(
        session, sbr_rules.project, "sbr.example", reason="test", now=NOW
    )
    row = (await watchlist.due(session, NOW))[0]
    ctx, store = make_context(sbr_rules), MemoryObjectStore()
    screenshot: dict[str, Any] = {
        "url": "https://sbr.example/",
        "status": 200,
        "title": "Domain marketplace",
        "final_url": "https://sedo.com/sale/sbr.example",
        "text_excerpt": "This domain is for sale",
        "content_type": "text/html",
        "method": "sandbox-test",
        "captured_at": NOW.isoformat(),
        "artifacts": [
            {
                "name": "screenshot",
                "content_type": "image/png",
                "data_b64": base64.b64encode(b"png-evidence").decode(),
            },
            {
                "name": "html",
                "content_type": "text/html",
                "data_b64": base64.b64encode(b"<html>Buy this domain</html>").decode(),
            },
        ],
    }
    service = EnrichmentService(
        {
            "dns": static_enricher(ctx, "dns", DNS),
            "tls": static_enricher(ctx, "tls", {}),
            "http_probe": static_enricher(
                ctx,
                "http_probe",
                {
                    "reachable": True,
                    "status": 200,
                    "title": "SBR Login",
                    "has_password_field": True,
                    "brand_terms": ["SBR"],
                },
            ),
            "screenshot": static_enricher(ctx, "screenshot", lambda _: dict(screenshot)),
        },
        saver=store_saver(store),
        clock=lambda: NOW,
    )

    async def change(*_: Any) -> None:
        raise AssertionError("停放页不应在初次复查触发高风险重新评分")

    try:
        observation = await watchlist.recheck(
            session, row, enrichment=service, on_change=change, now=NOW
        )
        await session.refresh(observation, ["data"])
        assert row.state == "parked" and observation.data["page"]["source"] == "browser"
        assert (
            observation.data["page"]["verdict"] == "parking"
            and observation.data["capture_status"] == "done"
        )
        saved = (
            await session.scalars(
                select(Evidence).where(Evidence.watch_observation_id == observation.id)
            )
        ).all()
        assert {ev.kind for ev in saved} == {"screenshot", "html"}
        assert all(
            ev.finding_id is None and ev.source_url == screenshot["final_url"] for ev in saved
        )
        assert await session.scalar(select(Finding.id)) is None
        for ev in saved:
            assert await store.get(ev.object_key)
        assert "data_b64" not in str(observation.data)
        screenshot.clear()
        screenshot.update({"error": "sandbox_unavailable"})
        later = NOW + timedelta(hours=4)

        async def quiet(*_: Any) -> None:
            pass

        failed = await watchlist.recheck(
            session, row, enrichment=service, on_change=quiet, now=later
        )
        assert (
            failed.data["capture_status"] == "failed" and failed.data["page"]["source"] == "probe"
        )
        assert len((await session.scalars(select(Evidence))).all()) == 2
    finally:
        await ctx.http().aclose()


async def test_no_dns_skips_browser_and_still_records_check(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    await watchlist.ensure_watched(
        session, sbr_rules.project, "gone.example", reason="test", now=NOW
    )
    row = (await watchlist.due(session, NOW))[0]
    ctx = make_context(sbr_rules)
    browser = static_enricher(ctx, "screenshot", AssertionError("No navigation without DNS"))
    service = EnrichmentService(
        {"dns": static_enricher(ctx, "dns", {"nxdomain": True}), "screenshot": browser}
    )

    async def quiet(*_: Any) -> None:
        pass

    try:
        observation = await watchlist.recheck(
            session, row, enrichment=service, on_change=quiet, now=NOW
        )
        assert row.state == "no_dns" and browser.calls == []
        assert observation.data["capture_status"] == "no_web_address"
        assert await session.scalar(select(Evidence.id)) is None
    finally:
        await ctx.http().aclose()
