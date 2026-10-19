import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.connectors.mastodon_tags.connector import (
    MastodonTagsConnector,
    _hashtag,
    _instance,
    _status,
)
from opti.core.config import ProjectRules
from opti.db.models import Document, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context

CONFIG = {"instances": ["https://social.example"], "hashtags": ["SampleBrand"]}


def status(
    status_id: str, text: str, *, visibility: str = "public", **extra: Any
) -> dict[str, Any]:
    return {
        "id": status_id,
        "created_at": datetime.now(UTC).isoformat(),
        "visibility": visibility,
        "sensitive": False,
        "spoiler_text": "",
        "reblog": None,
        "content": f"<p>{text}</p>",
        "url": f"https://social.example/@writer/{status_id}",
        "language": "en",
        "account": {"acct": "must-not-be-stored", "note": "profile details"},
        **extra,
    }


async def resolve(_host: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


def connector(
    rules: ProjectRules, handler: Any, *, cursors: MemoryCursorStore | None = None, **config: Any
) -> MastodonTagsConnector:
    conn = MastodonTagsConnector(
        make_context(rules, connector_id="mastodon_tags", handler=handler, cursors=cursors),
        {**CONFIG, **config},
    )
    conn.resolve = resolve
    return conn


def test_default_blocked_and_config_validation(sbr_rules: ProjectRules) -> None:
    registry = Registry()
    manifest = registry.manifest("mastodon_tags")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.category == "social" and not instance.enabled and not instance.license_approved
    assert _instance("http://social.example") is None
    assert _instance("https://social.example/private") is None
    assert _instance("https://user@social.example") is None
    assert _instance("https://127.0.0.1") is None
    assert _hashtag("#SampleBrand") == "SampleBrand"
    assert _hashtag("Sample Brand") is None
    with pytest.raises(ValueError, match="instances"):
        connector(sbr_rules, lambda _r: httpx.Response(200), instances=[]).validate_config()
    with pytest.raises(ValueError, match="hashtags"):
        connector(sbr_rules, lambda _r: httpx.Response(200), hashtags=[]).validate_config()


def test_only_public_plain_text_statuses() -> None:
    assert _status(status("10", "Sample Brand", visibility="private")) is None
    assert _status(status("10", "Sample Brand", sensitive=True)) is None
    assert _status(status("10", "Sample Brand", spoiler_text="Content warning")) is None
    assert _status(status("10", "Sample Brand", reblog={"id": "9"})) is None
    assert _status(status("10", "Sample Brand", url="http://insecure.example/post")) is None
    parsed = _status(status("10", "Sample Brand &amp; partners"))
    assert parsed is not None and parsed[2] == "Sample Brand & partners"


async def test_tag_pagination_filter_and_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["host"] == "social.example"
        params = parse_qs(urlsplit(str(request.url)).query)
        if "max_id" not in params:
            return httpx.Response(
                200,
                json=[
                    status("103", "Fake Sample Brand loan offer. Pay a processing fee."),
                    status("102", "unrelated topic"),
                ],
            )
        assert params["max_id"] == ["102"]
        return httpx.Response(200, json=[status("101", "Sample Brand funds a project")])

    conn = connector(sbr_rules, handler, cursors=cursors, page_size=2)
    conn.validate_config()
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert [item.source_item_id for item in items] == [
        "https://social.example#103",
        "https://social.example#101",
    ]
    assert items[0].payload["document"]["source_name"] == "Mastodon · social.example"
    assert "must-not-be-stored" not in json.dumps(items[0].payload)
    assert len(requests) == 2
    assert requests[0].url.path == "/api/v1/timelines/tag/SampleBrand"
    assert parse_qs(urlsplit(str(requests[0].url)).query)["limit"] == ["2"]
    assert list(cursors.dump("mastodon_tags").values()) == ["103"]
    [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert parse_qs(urlsplit(str(requests[2].url)).query)["since_id"] == ["103"]


async def test_page_cap_or_access_denial_does_not_advance_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    full = connector(
        sbr_rules,
        lambda _r: httpx.Response(200, json=[status("201", "Sample Brand")]),
        cursors=cursors,
        page_size=1,
        max_pages=1,
    )
    assert len([item async for item in full.fetch(build_query_plan(sbr_rules))]) == 1
    assert cursors.dump("mastodon_tags") == {}
    denied = connector(sbr_rules, lambda _r: httpx.Response(401), cursors=cursors)
    assert [item async for item in denied.fetch(build_query_plan(sbr_rules))] == []
    assert cursors.dump("mastodon_tags") == {}


async def test_private_dns_answer_is_blocked(sbr_rules: ProjectRules) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json=[])

    async def private_resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    conn = connector(sbr_rules, handler)
    conn.resolve = private_resolve
    assert [item async for item in conn.fetch(build_query_plan(sbr_rules))] == []
    assert requests == 0


@pytest.mark.db
async def test_mastodon_finding_scrubs_full_text(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    marker = "UNRELATED-PRIVATE-DETAIL-123"
    body = "Fake Sample Brand loan offer: pay a processing fee. "
    body += "Unrelated regional infrastructure project. " * 5 + marker
    conn = connector(sbr_rules, lambda _r: httpx.Response(200, json=[status("301", body)]))
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1
    result = await Processor(sbr_rules, EnrichmentService({})).process(session, items[0])
    assert len(result.findings) == 1 and len(result.alerts) == 1
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "fraud_scam"
    raw = (await session.scalars(select(RawItemRow))).one()
    doc = (await session.scalars(select(Document))).one()
    assert raw.payload["document"]["text"] == ""
    assert marker not in json.dumps(raw.payload)
    assert marker not in json.dumps(doc.contexts)
