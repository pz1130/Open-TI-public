import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.connectors.reddit_search.connector import RedditSearchConnector, _post
from opti.core.config import ProjectRules
from opti.db.models import Document, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.base import MissingCredential
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context

SECRETS = EnvSecretProvider(
    {
        "OPTI_SECRET_REDDIT_SEARCH_CLIENT_ID": "approved-app",
        "OPTI_SECRET_REDDIT_SEARCH_CLIENT_SECRET": "test-secret",
    }
)
CONFIG = {"user_agent": "Open-TI:approved-app:v0.1 (by /u/institution)"}


def submission(
    post_id: str, title: str, *, body: str = "", created: datetime | None = None, **extra: Any
) -> dict[str, Any]:
    return {
        "kind": "t3",
        "data": {
            "id": post_id,
            "name": f"t3_{post_id}",
            "title": title,
            "selftext": body,
            "created_utc": (created or datetime.now(UTC)).timestamp(),
            "subreddit": "finance",
            "author": "must-not-be-stored",
            **extra,
        },
    }


def connector(
    rules: ProjectRules, handler: Any, *, cursors: MemoryCursorStore | None = None, **config: Any
) -> RedditSearchConnector:
    return RedditSearchConnector(
        make_context(
            rules, connector_id="reddit_search", handler=handler, cursors=cursors, secrets=SECRETS
        ),
        {**CONFIG, **config},
    )


def test_disabled_until_explicit_api_approval() -> None:
    registry = Registry()
    manifest = registry.manifest("reddit_search")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.category == "social" and manifest.commercial_use == "restricted"
    assert not instance.enabled and not instance.license_approved
    assert {c.name for c in manifest.credentials if c.required} == {"client_id", "client_secret"}


def test_rejects_missing_identity_and_removed_posts(sbr_rules: ProjectRules) -> None:
    assert (
        _post({"id": "abc", "name": "t3_other", "title": "Sample Brand", "created_utc": 1})
        is None
    )
    assert (
        _post(submission("abc", "Sample Brand", removed_by_category="moderator")["data"])
        is None
    )
    assert (
        _post(submission("abc", "Sample Brand", is_robot_indexable=False)["data"]) is None
    )
    with pytest.raises(MissingCredential):
        RedditSearchConnector(
            make_context(sbr_rules, connector_id="reddit_search"), CONFIG
        ).validate_config()
    with pytest.raises(ValueError, match="user_agent"):
        connector(sbr_rules, lambda _r: httpx.Response(200), user_agent="bad").validate_config()


async def test_oauth_search_filter_and_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    seen: list[httpx.Request] = []
    when = datetime.now(UTC) - timedelta(minutes=2)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/v1/access_token":
            assert request.headers["authorization"].startswith("Basic ")
            assert request.content == b"grant_type=client_credentials"
            return httpx.Response(200, json={"access_token": "access-token", "expires_in": 3600})
        assert request.url.host == "oauth.reddit.com"
        assert request.headers["authorization"] == "Bearer access-token"
        return httpx.Response(
            200,
            json={
                "data": {
                    "children": [
                        submission("aaa111", "MySQL SBR Cluster 8.0"),
                        submission(
                            "bbb222",
                            "Fake Sample Brand loan offer",
                            body="Pay a processing fee.",
                            created=when,
                        ),
                        submission("ccc333", "unrelated institution"),
                        submission("bbb222", "Fake Sample Brand loan offer", created=when),
                    ],
                    "after": None,
                }
            },
        )

    conn = connector(sbr_rules, handler, cursors=cursors, max_queries=1)
    conn.validate_config()
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert [item.source_item_id for item in items] == ["t3_bbb222"]
    assert items[0].url == "https://www.reddit.com/comments/bbb222"
    assert items[0].payload["document"]["title"] == "Reddit 公开帖子"
    assert "processing fee" in items[0].payload["document"]["text"]
    assert items[0].payload["document"]["source_name"] == "Reddit r/finance"
    assert "must-not-be-stored" not in json.dumps(items[0].payload)
    params = parse_qs(urlsplit(str(seen[1].url)).query)
    assert params["q"] == ['"Sample Brand"']
    assert params["sort"] == ["new"] and params["type"] == ["link"]
    assert len(seen) == 2  # 一个 OAuth 请求、一个搜索请求
    assert (
        cursors.get(
            "reddit_search", "since:" + hashlib.sha256(b'"Sample Brand"').hexdigest()[:16]
        )
        is not None
    )


async def test_page_cap_does_not_advance_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/access_token":
            return httpx.Response(200, json={"access_token": "a", "expires_in": 3600})
        return httpx.Response(
            200,
            json={
                "data": {
                    "children": [submission("ddd444", "Sample Brand")],
                    "after": "t3_ddd444",
                }
            },
        )

    items = [
        item
        async for item in connector(
            sbr_rules, handler, cursors=cursors, max_queries=1, max_pages=1
        ).fetch(build_query_plan(sbr_rules))
    ]
    assert len(items) == 1 and cursors.dump("reddit_search") == {}


@pytest.mark.parametrize("status", [302, 403])
async def test_api_failure_does_not_advance_cursor(sbr_rules: ProjectRules, status: int) -> None:
    cursors = MemoryCursorStore()
    hosts: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.path == "/api/v1/access_token":
            return httpx.Response(200, json={"access_token": "a", "expires_in": 3600})
        return httpx.Response(
            status,
            headers={"Location": "https://unexpected.example/token"},
            json={"message": "approval required"},
        )

    items = [
        item
        async for item in connector(sbr_rules, handler, cursors=cursors, max_queries=1).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert items == [] and cursors.dump("reddit_search") == {}
    assert hosts == ["www.reddit.com", "oauth.reddit.com"]


async def test_expired_token_is_refreshed_once(sbr_rules: ProjectRules) -> None:
    tokens = 0
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal tokens, calls
        if request.url.path == "/api/v1/access_token":
            tokens += 1
            return httpx.Response(200, json={"access_token": f"token-{tokens}", "expires_in": 3600})
        calls += 1
        if calls == 1:
            assert request.headers["authorization"] == "Bearer token-1"
            return httpx.Response(401)
        assert request.headers["authorization"] == "Bearer token-2"
        return httpx.Response(200, json={"data": {"children": [], "after": None}})

    items = [
        item
        async for item in connector(sbr_rules, handler, max_queries=1).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert items == [] and tokens == 2 and calls == 2


@pytest.mark.db
async def test_reddit_finding_stores_excerpt_not_post_body(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    marker = "UNRELATED-PRIVATE-DETAIL-123"
    long_body = (
        "Pay a processing fee. " + "Unrelated regional infrastructure project. " * 5 + marker
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/access_token":
            return httpx.Response(200, json={"access_token": "a", "expires_in": 3600})
        return httpx.Response(
            200,
            json={
                "data": {
                    "children": [
                        submission("eee555", "Fake Sample Brand loan offer", body=long_body)
                    ],
                    "after": None,
                }
            },
        )

    conn = connector(sbr_rules, handler, max_queries=1)
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1
    item = items[0]
    result = await Processor(sbr_rules, EnrichmentService({})).process(session, item)
    assert len(result.findings) == 1 and len(result.alerts) == 1
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "fraud_scam"
    raw = (await session.scalars(select(RawItemRow))).one()
    document = (await session.scalars(select(Document))).one()
    assert raw.payload["document"]["text"] == ""
    assert marker not in json.dumps(raw.payload)
    assert marker not in json.dumps(document.contexts)
