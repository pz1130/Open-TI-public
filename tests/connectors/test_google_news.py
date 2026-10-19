from urllib.parse import parse_qs, urlsplit

import httpx

from opti.connectors.google_news.connector import (
    DEFAULT_EDITIONS,
    GoogleNewsConnector,
    edition_queries,
)
from opti.core.config import ProjectRules
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

RSS = b"""<rss version="2.0"><channel><title>Google News</title>
<item><title>Sample Brand issues bond - Example Paper</title>
<link>https://news.google.com/rss/articles/CBMiXYZ</link><guid isPermaLink="false">CBMiXYZ</guid>
<pubDate>Thu, 02 Oct 2026 08:00:00 GMT</pubDate>
<description>&lt;a href="https://news.google.com/rss/articles/CBMiXYZ"&gt;Sample Brand issues bond&lt;/a&gt;</description>
<source url="https://paper.example">Example Paper</source></item></channel></rss>"""


def test_editions_pick_terms_by_script(sbr_rules: ProjectRules) -> None:
    pairs = edition_queries(build_query_plan(sbr_rules), DEFAULT_EDITIONS, limit=50)
    en = [q for ed, q in pairs if ed["hl"] == "en-US"]
    zh = [q for ed, q in pairs if ed["hl"] == "zh-CN"]
    assert '"Sample Brand"' in en and '"Образцовый бренд"' in en
    assert '"样本品牌"' in zh and not any("Bank" in q for q in zh)
    assert not any("SBR" in q for _, q in pairs)  # 缩写不外发
    assert len(edition_queries(build_query_plan(sbr_rules), DEFAULT_EDITIONS, limit=3)) == 3


async def test_google_news_items(sbr_rules: ProjectRules) -> None:
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(
            "https://news.google.com/rss/search?"
        )  # 不访问文章跳转链接
        seen.append(parse_qs(urlsplit(str(request.url)).query))
        return httpx.Response(200, content=RSS, headers={"content-type": "application/xml"})

    cursors = MemoryCursorStore()
    conn = GoogleNewsConnector(
        make_context(sbr_rules, connector_id="google_news", handler=handler, cursors=cursors),
        {"max_queries": 2},
    )
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert len(seen) == 2 and seen[0]["hl"] == ["en-US"] and seen[0]["ceid"] == ["US:en"]
    doc = items[0].payload["document"]
    assert doc["source_name"] == "Example Paper" and doc["text"] == "" and doc["language"] == "en"
    assert (
        doc["summary"] == "Sample Brand issues bond"
        and items[0].source_item_id == "CBMiXYZ"
    )
    again = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert len(again) == 2  # 游标重叠窗口内的条目仍会产出，由处理器去重


async def test_html_error_page_is_ignored(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>unusual traffic</body></html>")

    conn = GoogleNewsConnector(
        make_context(sbr_rules, connector_id="google_news", handler=handler), {}
    )
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
