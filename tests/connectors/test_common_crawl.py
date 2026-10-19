import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.connectors.common_crawl.connector import CommonCrawlConnector, _candidate, _capture
from opti.core.config import ProjectRules
from opti.core.urls import UrlMatcher
from opti.db.models import Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context

URL = "https://sample-brand-login.example/"


def connector(rules: ProjectRules, handler: Any, **config: Any) -> CommonCrawlConnector:
    return CommonCrawlConnector(
        make_context(rules, connector_id="common_crawl", handler=handler),
        {"candidate_urls": [URL], **config},
    )


def record(url: str = URL, **extra: Any) -> dict[str, Any]:
    return {
        "url": url,
        "timestamp": "20260915123456",
        "status": "200",
        "mime": "text/html",
        "digest": "ABCDEF12345",
        "filename": "must-not-be-retained.warc.gz",
        **extra,
    }


def test_manifest_and_candidate_validation(sbr_rules: ProjectRules) -> None:
    manifest = Registry().manifest("common_crawl")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.kind == ("batch",)
    assert not instance.enabled and not instance.license_approved
    assert _candidate(URL, UrlMatcher(sbr_rules)) == URL
    for invalid in (
        "https://user:password@sample-brand-login.example/",
        "https://sample-brand-login.example/?token=secret",
        "http://[broken",
        "http://127.0.0.1/sample-brand",
        "https://example.com/no-brand",
    ):
        with pytest.raises(ValueError, match="candidate_urls"):
            connector(
                sbr_rules, lambda _r: httpx.Response(200), candidate_urls=[invalid]
            ).validate_config()
    assert _capture(record(url="https://evil.example/"), URL) is None
    assert _capture(record(status="404"), URL) is None
    assert _capture(record(timestamp="20261315123456"), URL) is None


async def test_exact_url_query_bounded_to_latest_crawls(sbr_rules: ProjectRules) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/collinfo.json":
            return httpx.Response(
                200,
                json=[
                    {"id": "CC-MAIN-2026-34", "cdx-api": "https://evil.example/"},
                    {"id": "CC-MAIN-2026-39"},
                    {"id": "CC-MAIN-2026-37"},
                    {"id": "bad/../id"},
                ],
            )
        if request.url.path == "/CC-MAIN-2026-39-index":
            entries = [
                record(),
                record(url="https://evil.example/"),
                record(status="302"),
                record(mime="application/pdf"),
            ]
        else:
            entries = [record(timestamp="20260815123456")]
        return httpx.Response(200, text="\n".join(json.dumps(entry) for entry in entries))

    conn = connector(sbr_rules, handler)
    conn.validate_config()
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1 and items[0].source_item_id == f"{URL}#20260915123456"
    assert items[0].payload["intel"]["confirmed"] is False
    assert items[0].payload["intel"]["crawl_id"] == "CC-MAIN-2026-39"
    assert items[0].payload["intel"]["capture_time"] == "2026-09-15T12:34:56+00:00"
    assert "must-not-be-retained" not in json.dumps(items[0].payload)
    assert [request.url.path for request in requests] == [
        "/collinfo.json",
        "/CC-MAIN-2026-39-index",
        "/CC-MAIN-2026-37-index",
    ]
    assert all(request.url.host == "index.commoncrawl.org" for request in requests)
    params = parse_qs(urlsplit(str(requests[1].url)).query)
    assert params["url"] == [URL] and params["matchType"] == ["exact"]
    assert params["limit"] == ["10"] and params["sort"] == ["reverse"]


async def test_missing_capture_and_rate_limit(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/collinfo.json":
            return httpx.Response(200, json=[{"id": "CC-MAIN-2026-39"}])
        return httpx.Response(404)

    assert [
        item async for item in connector(sbr_rules, handler).fetch(build_query_plan(sbr_rules))
    ] == []

    def limited(request: httpx.Request) -> httpx.Response:
        return handler(request) if request.url.path == "/collinfo.json" else httpx.Response(429)

    assert [
        item async for item in connector(sbr_rules, limited).fetch(build_query_plan(sbr_rules))
    ] == []
    assert [
        item
        async for item in connector(sbr_rules, handler, candidate_urls=[]).fetch(
            build_query_plan(sbr_rules)
        )
    ] == []


@pytest.mark.db
async def test_archive_hit_creates_unconfirmed_url_finding(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/collinfo.json":
            return httpx.Response(200, json=[{"id": "CC-MAIN-2026-39"}])
        return httpx.Response(200, text=json.dumps(record()))

    items = [
        item async for item in connector(sbr_rules, handler).fetch(build_query_plan(sbr_rules))
    ]
    result = await Processor(sbr_rules, EnrichmentService({}), enrich_ids=()).process(
        session, items[0]
    )
    assert len(result.findings) == 1
    finding = await session.get(Finding, result.findings[0])
    raw = (await session.scalars(select(RawItemRow))).one()
    assert finding is not None and "common_crawl" in finding.sources
    assert raw.payload["intel"]["confirmed"] is False
    assert "filename" not in raw.payload["intel"]
