from typing import Any

import httpx

from opti.connectors.rss_feeds.connector import RssFeedsConnector
from opti.core.config import ProjectRules
from opti.core.feeds import MAX_FEED_BYTES
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

PARA = (
    "<p>"
    + "The Sample Brand approved a new loan to support renewable energy projects. " * 8
    + "</p>"
)
ARTICLE = f"<html lang='en'><head><title>Full</title></head><body><article>{PARA * 3}</article></body></html>"


def _rss(*items: tuple[str, str, str]) -> bytes:
    body = "".join(
        f"<item><title>{t}</title><link>https://news.example/{g}</link><guid>{g}</guid><pubDate>{d}</pubDate></item>"
        for t, g, d in items
    )
    return f"<rss version='2.0'><channel><title>Example</title>{body}</channel></rss>".encode()


async def _resolve(host: str, port: int) -> list[str]:
    return [host if host == "127.0.0.1" else "93.184.216.34"]


async def _run(
    rules: ProjectRules, feeds: dict[str, bytes], config: dict[str, Any], cursors: MemoryCursorStore
) -> tuple[list[Any], list[str]]:
    fetched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "news.example":
            fetched.append(request.url.path)
            return httpx.Response(200, html=ARTICLE)
        original = (
            f"{request.url.scheme}://{request.headers['host']}{request.url.raw_path.decode()}"
        )
        body = feeds.get(original)
        return (
            httpx.Response(200, content=body, headers={"content-type": "application/rss+xml"})
            if body
            else httpx.Response(404)
        )

    conn = RssFeedsConnector(
        make_context(rules, connector_id="rss_feeds", handler=handler, cursors=cursors), config
    )
    conn.resolve = _resolve
    return [i async for i in conn.fetch(build_query_plan(rules))], fetched


D1 = "Thu, 02 Oct 2026 08:00:00 +0000"


async def test_prefilter_controls_fetching(sbr_rules: ProjectRules) -> None:
    feeds = {
        "https://feeds.example/media": _rss(
            ("Sample Brand approves loan", "a1", D1), ("Weather update", "a2", D1)
        ),
        "https://feeds.example/cert": _rss(("Advisory 2026-17", "c1", D1)),
    }
    config = {"feeds": [{"url": "https://feeds.example/media", "name": "Media", "language": "en"},
                        {"url": "https://feeds.example/cert", "name": "CERT", "fetch_all": True},
                        {"url": "ftp://feeds.example/x"}]}  # fmt: skip
    items, fetched = await _run(sbr_rules, feeds, config, MemoryCursorStore())
    assert [i.source_item_id for i in items] == [
        "https://feeds.example/media#a1",
        "https://feeds.example/cert#c1",
    ]
    assert fetched == ["/a1", "/c1"]  # 无关条目不抓正文、不产出
    doc = items[0].payload["document"]
    assert (
        doc["source_name"] == "Media"
        and doc["language"] == "en"
        and "renewable energy" in doc["text"]
    )


async def test_cursor_skips_old_items(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    url = "https://feeds.example/media"
    config = {"feeds": [{"url": url}]}
    first = {url: _rss(("Sample Brand news", "n1", D1))}
    assert len((await _run(sbr_rules, first, config, cursors))[0]) == 1
    later = {url: _rss(
        ("Sample Brand news 2", "n2", "Thu, 02 Oct 2026 10:00:00 +0000"),
        ("Sample Brand news (late)", "n0", "Thu, 02 Oct 2026 07:30:00 +0000"),  # 1 小时重叠内
        ("Sample Brand old news", "old", "Wed, 01 Oct 2026 08:00:00 +0000"),
    )}  # fmt: skip
    items, _ = await _run(sbr_rules, later, config, cursors)
    assert [i.source_item_id.rsplit("#", 1)[1] for i in items] == ["n2", "n0"]


async def test_one_bad_feed_does_not_stop_others(sbr_rules: ProjectRules) -> None:
    xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x;</title></item></channel></rss>'
    feeds = {
        "https://feeds.example/bad": xxe,
        "https://feeds.example/good": _rss(("Sample Brand", "g1", D1)),
    }
    config = {"feeds": [{"url": "https://feeds.example/bad"}, {"url": "https://feeds.example/missing"},
                        {"url": "https://feeds.example/good"}]}  # fmt: skip
    items, _ = await _run(sbr_rules, feeds, config, MemoryCursorStore())
    assert [i.source_item_id for i in items] == ["https://feeds.example/good#g1"]


async def test_private_feed_and_redirect_are_blocked(sbr_rules: ProjectRules) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.headers["host"])
        return httpx.Response(302, headers={"location": "http://127.0.0.1/internal"})

    conn = RssFeedsConnector(
        make_context(sbr_rules, connector_id="rss_feeds", handler=handler),
        {"feeds": [{"url": "http://127.0.0.1/feed"}, {"url": "https://feeds.example/redirect"}]},
    )
    conn.resolve = _resolve
    assert [item async for item in conn.fetch(build_query_plan(sbr_rules))] == []
    assert requested == ["feeds.example"]


async def test_oversized_feed_is_rejected_without_blocking_next(sbr_rules: ProjectRules) -> None:
    feeds = {
        "https://feeds.example/huge": b"x" * (MAX_FEED_BYTES + 1),
        "https://feeds.example/good": _rss(("Sample Brand", "ok", D1)),
    }
    config = {"feeds": [{"url": url} for url in feeds]}
    items, _ = await _run(sbr_rules, feeds, config, MemoryCursorStore())
    assert [item.source_item_id for item in items] == ["https://feeds.example/good#ok"]


async def test_malformed_article_link_does_not_stop_feed(sbr_rules: ProjectRules) -> None:
    body = (
        b"<rss><channel>"
        b"<item><title>Sample Brand one</title><guid>bad</guid><link>http://[bad</link></item>"
        b"<item><title>Sample Brand two</title><guid>good</guid>"
        b"<link>https://news.example/good</link></item></channel></rss>"
    )
    url = "https://feeds.example/news"
    items, _ = await _run(sbr_rules, {url: body}, {"feeds": [{"url": url}]}, MemoryCursorStore())
    assert [item.payload["document"]["url"] for item in items] == [
        None,
        "https://news.example/good",
    ]
