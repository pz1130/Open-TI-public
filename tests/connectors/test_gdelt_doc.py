from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from opti.connectors.gdelt_doc.connector import GdeltDocConnector
from opti.core.config import ProjectRules
from opti.sdk.context import MemoryCursorStore
from opti.sdk.models import QueryPlan, SearchTerm
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

PARA = (
    "<p>"
    + "The Sample Brand approved a new loan to support renewable energy projects. " * 8
    + "</p>"
)
ARTICLES = {"articles": [
    {"url": "https://news.example/a", "title": "Bank approves loan", "seendate": "20261002T081500Z",
     "domain": "news.example", "language": "English", "sourcecountry": "United States"},
    {"url": "https://zh.example/b", "title": "样本银行", "seendate": "20261002T090000Z", "domain": "zh.example",
     "language": "Chinese"},
    {"url": "javascript:alert(1)", "title": "bad", "seendate": "20261002T090000Z"},
]}  # fmt: skip


async def _resolve(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def _conn(
    rules: ProjectRules, handler: Any, cursors: MemoryCursorStore, **config: Any
) -> GdeltDocConnector:
    conn = GdeltDocConnector(
        make_context(rules, connector_id="gdelt_doc", handler=handler, cursors=cursors), config
    )
    conn.resolve = _resolve
    return conn


def test_compile_queries(sbr_rules: ProjectRules) -> None:
    conn = _conn(sbr_rules, lambda _r: httpx.Response(200), MemoryCursorStore())
    assert conn.compile_queries(build_query_plan(sbr_rules)) == [
        '("Sample Brand" OR "ORBIT Bank" OR "ORBIT Development Bank" OR "Marca de Exemplo")'
    ]  # 中文、俄文不发送（GDELT 按英文译文检索）；缩写不外发


async def test_window_and_cursor(sbr_rules: ProjectRules) -> None:
    params: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.gdeltproject.org":
            params.append(parse_qs(urlsplit(str(request.url)).query))
            return httpx.Response(200, json=ARTICLES)
        return httpx.Response(
            200, html=f"<html lang='en'><body><article>{PARA * 3}</article></body></html>"
        )

    cursors = MemoryCursorStore()
    items = [i async for i in _conn(sbr_rules, handler, cursors).fetch(build_query_plan(sbr_rules))]
    p = params[0]
    assert p["mode"] == ["ArtList"] and p["format"] == ["json"] and p["maxrecords"] == ["250"]
    start = datetime.strptime(p["startdatetime"][0], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    assert abs(start - (datetime.now(UTC) - timedelta(days=1))) < timedelta(minutes=5)
    docs = [i.payload["document"] for i in items]
    assert [d["url"] for d in docs] == ["https://news.example/a", "https://zh.example/b"]
    assert (
        docs[0]["language"] == "en"
        and docs[1]["language"] == "zh"
        and docs[0]["source_name"] == "news.example"
    )
    assert (
        docs[0]["published_at"] == "2026-10-02T08:15:00+00:00"
        and "renewable energy" in docs[0]["text"]
    )
    assert cursors.get("gdelt_doc", "since") == "2026-10-02T09:00:00+00:00"
    [i async for i in _conn(sbr_rules, handler, cursors).fetch(build_query_plan(sbr_rules))]
    assert params[1]["startdatetime"] == ["20261002080000"]  # 游标 − 1 小时


async def test_errors_do_not_advance_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    cursors.set("gdelt_doc", "since", "2026-10-02T09:00:00+00:00")
    for status, body in ((200, "Please limit requests to one every 5 seconds"), (429, "slow down")):
        conn = _conn(sbr_rules, lambda _r, s=status, b=body: httpx.Response(s, text=b), cursors)
        assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
        assert cursors.get("gdelt_doc", "since") == "2026-10-02T09:00:00+00:00"
    empty = _conn(sbr_rules, lambda _r: httpx.Response(200, json={}), cursors)
    assert [
        i async for i in empty.fetch(build_query_plan(sbr_rules))
    ] == []  # 没有结果时 GDELT 返回 {}


async def test_duplicate_article_across_queries_is_fetched_once(sbr_rules: ProjectRules) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"articles": [ARTICLES["articles"][0]]})

    plan = QueryPlan(
        project_ids=(sbr_rules.project,),
        terms=tuple(SearchTerm(f"Brand {i}", "phrase") for i in range(6)),
    )
    conn = _conn(sbr_rules, handler, MemoryCursorStore(), max_articles=0)
    items = [item async for item in conn.fetch(plan)]
    assert requests == 2
    assert [item.source_item_id for item in items] == ["https://news.example/a"]
