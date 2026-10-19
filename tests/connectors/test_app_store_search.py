import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.connectors.app_store_search.connector import AppStoreSearchConnector, _app
from opti.core.config import ProjectRules
from opti.db.models import Document, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context


def app(
    app_id: int, name: str, developer: str = "Unverified Studio", **extra: Any
) -> dict[str, Any]:
    return {
        "kind": "software",
        "trackId": app_id,
        "trackName": name,
        "artistName": developer,
        "releaseDate": "2026-10-01T12:00:00Z",
        "trackViewUrl": "https://evil.example/redirect",
        "artworkUrl100": "https://evil.example/icon.png",
        "screenshotUrls": ["https://evil.example/screenshot.png"],
        "description": "UNRELATED-PRIVATE-DETAIL-123",
        **extra,
    }


def connector(rules: ProjectRules, handler: Any, **config: Any) -> AppStoreSearchConnector:
    return AppStoreSearchConnector(
        make_context(rules, connector_id="app_store_search", handler=handler),
        {"countries": ["US"], "max_queries": 1, **config},
    )


def test_config_and_app_validation(sbr_rules: ProjectRules) -> None:
    registry = Registry()
    manifest = registry.manifest("app_store_search")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert (
        manifest.category == "app_store" and not instance.enabled and not instance.license_approved
    )
    with pytest.raises(ValueError, match="countries"):
        connector(sbr_rules, lambda _r: httpx.Response(200), countries=[]).validate_config()
    with pytest.raises(ValueError, match="countries"):
        connector(sbr_rules, lambda _r: httpx.Response(200), countries=["usa"]).validate_config()
    assert _app(app(1, "SBR")) is not None
    assert _app(app(1, "SBR", kind="software-package")) is not None
    assert _app(app(True, "SBR")) is None
    assert _app(app(1, "SBR", kind="song")) is None
    assert _app(app(1, " ")) is None


async def test_search_filters_metadata_and_uses_canonical_link(sbr_rules: ProjectRules) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "resultCount": 4,
                "results": [
                    app(123, "Sample Brand Loans"),
                    app(124, "Unrelated app", "Sample Brand Studio"),
                    app(125, "Unrelated app"),
                    app(123, "Sample Brand Loans"),
                ],
            },
        )

    conn = connector(sbr_rules, handler)
    conn.validate_config()
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert [item.source_item_id for item in items] == ["app:123", "app:124"]
    assert items[0].url == "https://apps.apple.com/app/id123"
    assert items[0].payload["document"]["title"] == "App Store 应用候选"
    assert items[0].payload["document"]["source_name"] == "Apple App Store · US"
    payload = json.dumps(items[0].payload)
    assert "evil.example" not in payload and "UNRELATED-PRIVATE-DETAIL-123" not in payload
    assert len(requests) == 1 and requests[0].url.path == "/search"
    params = parse_qs(urlsplit(str(requests[0].url)).query)
    assert params["country"] == ["US"]
    assert params["media"] == ["software"] and params["entity"] == ["software"]
    assert params["limit"] == ["50"]


async def test_api_error_and_invalid_response_emit_nothing(sbr_rules: ProjectRules) -> None:
    for response in (
        httpx.Response(429),
        httpx.Response(200, json={"results": {"bad": "shape"}}),
        httpx.Response(302, headers={"location": "https://evil.example/"}),
    ):
        conn = connector(sbr_rules, lambda _r, response=response: response)
        assert [item async for item in conn.fetch(build_query_plan(sbr_rules))] == []


@pytest.mark.db
async def test_candidate_enters_document_pipeline_without_promo_assets(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    conn = connector(
        sbr_rules,
        lambda _r: httpx.Response(200, json={"results": [app(301, "Sample Brand Loans")]}),
    )
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1
    result = await Processor(sbr_rules, EnrichmentService({})).process(session, items[0])
    assert len(result.findings) == 1
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "brand_mention"
    raw = (await session.scalars(select(RawItemRow))).one()
    doc = (await session.scalars(select(Document))).one()
    assert raw.payload["document"]["text"] == ""
    assert doc.url_normalized == "https://apps.apple.com/app/id301"
    assert "evil.example" not in json.dumps(raw.payload)
