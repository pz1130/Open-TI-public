from collections.abc import AsyncIterator
from typing import ClassVar

import httpx

from opti.connectors.newsbase import NewsConnector
from opti.core.config import ProjectRules
from opti.sdk.models import QueryPlan, RawItem, Tier
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

PARA = (
    "<p>"
    + "The Sample Brand approved a new loan to support renewable energy projects. " * 8
    + "</p>"
)


class Demo(NewsConnector):
    id: ClassVar[str] = "demo_news"
    tier: ClassVar[Tier] = Tier.FREE

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        for i in range(3):
            yield await self.document_item(
                plan, item_id=f"https://news.example/{i}", url=f"https://news.example/{i}", title=f"T{i}",
                summary="S", language=None, published=None, source_name="Example", query="q", fetch=True,
            )  # fmt: skip


async def _resolve(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


async def test_article_budget_and_fallback(sbr_rules: ProjectRules) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/1":
            return httpx.Response(500)
        return httpx.Response(
            200,
            html=f"<html lang='en'><head><title>Full</title></head><body><article>{PARA * 3}</article></body></html>",
        )

    conn = Demo(
        make_context(sbr_rules, connector_id="demo_news", handler=handler), {"max_articles": 2}
    )
    conn.resolve = _resolve
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    docs = [i.payload["document"] for i in items]
    assert "renewable energy" in docs[0]["text"] and docs[0]["language"] == "en"
    assert docs[1]["text"] == "" and docs[1]["title"] == "T1"  # 抓取失败：退回标题与摘要
    assert docs[2]["text"] == ""  # 超出每轮 2 篇的预算：不再抓取
    assert len([c for c in calls if c in ("/0", "/1", "/2")]) <= 3 and "/2" not in calls
    assert items[0].source_item_id == "https://news.example/0" and items[0].project_ids == (
        sbr_rules.project,
    )


async def test_long_source_ids_keep_distinct_hashes(sbr_rules: ProjectRules) -> None:
    conn = Demo(make_context(sbr_rules, connector_id="demo_news"), {})
    plan = build_query_plan(sbr_rules)
    first = await conn.document_item(
        plan,
        item_id="a" * 600 + "1",
        url=None,
        title="One",
        summary="",
        language=None,
        published=None,
        source_name="Example",
        query=None,
        fetch=False,
    )
    second = await conn.document_item(
        plan,
        item_id="a" * 600 + "2",
        url=None,
        title="Two",
        summary="",
        language=None,
        published=None,
        source_name="Example",
        query=None,
        fetch=False,
    )
    assert len(first.source_item_id) <= 500
    assert first.source_item_id != second.source_item_id
