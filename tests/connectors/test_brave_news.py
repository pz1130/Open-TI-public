from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from opti.connectors.brave_news.connector import BraveNewsConnector
from opti.core.config import ProjectRules
from opti.sdk.base import MissingCredential
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

SECRETS = EnvSecretProvider({"OPTI_SECRET_BRAVE_NEWS_API_KEY": "b" * 30})
RESULTS = {"type": "news", "results": [
    {"title": "<strong>Sample Brand</strong> issues bond", "url": "https://news.example/a",
     "description": "The <strong>Sample Brand</strong> issued a bond.", "page_age": "2026-10-02T08:00:00",
     "meta_url": {"hostname": "news.example"}},
]}  # fmt: skip


async def test_brave_search(sbr_rules: ProjectRules) -> None:
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-subscription-token"] == "b" * 30
        seen.append(parse_qs(urlsplit(str(request.url)).query))
        return httpx.Response(200, json=RESULTS)

    conn = BraveNewsConnector(make_context(sbr_rules, connector_id="brave_news", handler=handler, secrets=SECRETS),
                              {"max_queries": 2, "max_articles": 0})  # fmt: skip
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert (
        len(seen) == 2
        and seen[0]["q"] == ['"Sample Brand"']
        and seen[0]["freshness"] == ["pd"]
    )
    doc = items[0].payload["document"]
    assert (
        doc["title"] == "Sample Brand issues bond"
        and doc["summary"] == "The Sample Brand issued a bond."
    )
    assert (
        doc["source_name"] == "news.example" and doc["published_at"] == "2026-10-02T08:00:00+00:00"
    )


async def test_brave_errors(sbr_rules: ProjectRules) -> None:
    queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        queries.append(parse_qs(urlsplit(str(request.url)).query)["q"][0])
        return httpx.Response(429, json={"error": "rate limited"})

    conn = BraveNewsConnector(
        make_context(sbr_rules, connector_id="brave_news", handler=handler, secrets=SECRETS), {}
    )
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
    # 测试客户端对 429 重试一次；第一个查询失败后停止本轮（额度可能已用完），不再发送其他查询
    assert queries == ['"Sample Brand"'] * 2
    with pytest.raises(MissingCredential):
        BraveNewsConnector(make_context(sbr_rules, connector_id="brave_news"), {}).validate_config()


async def test_brave_cursor_skips_old_results(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    age = "2026-10-02T08:00:00"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {**RESULTS["results"][0], "url": "https://news.example/" + age, "page_age": age}
                ]
            },
        )

    conn = BraveNewsConnector(
        make_context(
            sbr_rules, connector_id="brave_news", handler=handler, secrets=SECRETS, cursors=cursors
        ),
        {"max_queries": 1, "max_articles": 0},
    )
    assert len([item async for item in conn.fetch(build_query_plan(sbr_rules))]) == 1
    age = "2026-10-02T06:00:00"
    assert [item async for item in conn.fetch(build_query_plan(sbr_rules))] == []
