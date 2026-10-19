import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from websockets.asyncio.server import ServerConnection, serve

from opti.connectors.bluesky_jetstream.connector import BlueskyJetstreamConnector, _event, _url
from opti.core.config import ProjectRules
from opti.db.models import Document, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context

DID = "did:plc:eygmaihciaxprqvxpfvl6flk"


def post(text: str, *, rkey: str = "3l3qo2vuowo2b", time_us: int | None = None) -> str:
    observed = time_us or int((datetime.now(UTC) - timedelta(minutes=1)).timestamp() * 1_000_000)
    return json.dumps(
        {
            "kind": "commit",
            "did": DID,
            "time_us": observed,
            "commit": {
                "operation": "create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": text,
                    "createdAt": "2026-10-04T00:00:00Z",
                    "langs": ["en"],
                    "embed": {"external": {"uri": "https://private.example"}},
                },
            },
        }
    )


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        b"\xff",
        "[]",
        json.dumps({"kind": "identity"}),
        post("Sample Brand").replace('"create"', '"delete"'),
        post("Sample Brand").replace('"app.bsky.feed.post"', '"app.bsky.feed.like"'),
        post("Sample Brand").replace(DID, "bad/did"),
        post("Sample Brand").replace('"text": "Sample Brand"', '"text": 7'),
    ],
)
def test_parser_rejects_non_post_and_malformed(raw: str | bytes) -> None:
    assert _event(raw) is None


def test_cursor_url_rewinds_and_keeps_post_filter() -> None:
    parsed = parse_qs(urlsplit(_url("wss://jetstream.test/subscribe?cursor=3", 20_000_000)).query)
    assert parsed == {"wantedCollections": ["app.bsky.feed.post"], "cursor": ["15000000"]}


def test_default_is_blocked_until_review() -> None:
    registry = Registry()
    manifest = registry.manifest("bluesky_jetstream")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.category == "social" and manifest.kind == ("stream",)
    assert instance.enabled is False and instance.license_approved is False


async def test_filters_before_return_and_resumes_with_overlap(sbr_rules: ProjectRules) -> None:
    cursor = MemoryCursorStore()
    base = int((datetime.now(UTC) - timedelta(minutes=1)).timestamp() * 1_000_000)
    paths: list[str] = []

    async def handler(ws: ServerConnection) -> None:
        paths.append(ws.request.path)
        if len(paths) == 1:
            await ws.send(post("A generic post", time_us=base))
            await ws.send(
                post(
                    "Fake Sample Brand loan offer: pay a processing fee.",
                    time_us=base + 6_000_000,
                )
            )
        else:
            await ws.send(
                post(
                    "Fake Sample Brand loan offer: pay a processing fee.",
                    time_us=base + 6_000_000,
                )
            )
            await ws.send(
                post(
                    "The Sample Brand opened a new office.",
                    rkey="post2",
                    time_us=base + 7_000_000,
                )
            )

    async with serve(handler, "127.0.0.1", 0) as server:
        port = next(iter(server.sockets)).getsockname()[1]
        connector = BlueskyJetstreamConnector(
            make_context(sbr_rules, connector_id="bluesky_jetstream", cursors=cursor),
            {
                "url": f"ws://127.0.0.1:{port}/subscribe",
                "max_reconnects": 1,
                "reconnect_max_delay": 0,
            },
        )
        items = [item async for item in connector.fetch(build_query_plan(sbr_rules))]

    assert len(items) == 3  # 回放包含重叠；确定性 item_id 负责下游幂等
    assert items[0].item_id == items[1].item_id != items[2].item_id
    assert items[0].source_item_id == f"at://{DID}/app.bsky.feed.post/3l3qo2vuowo2b"
    assert items[0].url == f"https://bsky.app/profile/{DID}/post/3l3qo2vuowo2b"
    assert items[0].payload == {
        "document": {
            "url": items[0].url,
            "title": "Bluesky 公开帖子",
            "summary": "",
            "text": "Fake Sample Brand loan offer: pay a processing fee.",
            "language": "en",
            "published_at": datetime.fromtimestamp((base + 6_000_000) / 1_000_000, UTC).isoformat(),
            "source_name": "Bluesky",
            "query": None,
        }
    }
    assert items[0].project_ids == (sbr_rules.project,)
    assert parse_qs(urlsplit(paths[0]).query) == {"wantedCollections": ["app.bsky.feed.post"]}
    assert parse_qs(urlsplit(paths[1]).query)["cursor"] == [str(base + 1_000_000)]
    assert cursor.get("bluesky_jetstream", "time_us") == str(base + 6_000_000)


@pytest.mark.db
async def test_matching_post_enters_pipeline_without_full_text(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    marker = "UNRELATED-PRIVATE-DETAIL-123"
    connector = BlueskyJetstreamConnector(
        make_context(sbr_rules, connector_id="bluesky_jetstream"), {"url": "ws://unused"}
    )
    event = connector.to_item(
        post(
            "Fake Sample Brand loan offer: pay a processing fee. "
            + "This is a public discussion about unrelated regional infrastructure. " * 3
            + marker
        ),
        build_query_plan(sbr_rules),
    )
    assert event is not None
    result = await Processor(sbr_rules, EnrichmentService({})).process(session, event[0])
    assert len(result.findings) == 1 and len(result.alerts) == 1
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "fraud_scam"
    raw = (await session.scalars(select(RawItemRow))).one()
    document = (await session.scalars(select(Document))).one()
    assert raw.payload["document"]["text"] == ""
    assert marker not in json.dumps(raw.payload)
    assert marker not in json.dumps(document.contexts)
    assert document.url == event[0].url
