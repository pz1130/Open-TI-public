from typing import Any

import httpx

from opti.connectors.articles import fetch_article
from opti.core.config import ProjectRules
from opti.sdk.safefetch import SafeFetcher
from opti.sdk.testing import make_context

PARAGRAPH = "<p>" + "The Sample Brand approved a new renewable energy loan. " * 8 + "</p>"


async def _resolve(host: str, port: int) -> list[str]:
    return {"news.example": ["93.184.216.34"], "internal.example": ["10.1.2.3"]}.get(host, [])


def _fetcher(rules: ProjectRules, handler: Any) -> SafeFetcher:
    return SafeFetcher(make_context(rules, handler=handler).http(), resolve=_resolve)


async def test_fetch_article(sbr_rules: ProjectRules) -> None:
    html = (
        "<html lang='en'><head><title>T</title></head><body><article>"
        + PARAGRAPH * 3
        + "</article></body></html>"
    )
    article = await fetch_article(
        _fetcher(
            sbr_rules,
            lambda _: httpx.Response(200, text=html, headers={"content-type": "text/html"}),
        ),
        "https://news.example/a",
    )
    assert article is not None and "renewable energy" in article.text


async def test_rejects_non_html_and_private(sbr_rules: ProjectRules) -> None:
    pdf = lambda _: httpx.Response(  # noqa: E731
        200, content=b"%PDF-1.7", headers={"content-type": "application/pdf"}
    )
    assert await fetch_article(_fetcher(sbr_rules, pdf), "https://news.example/a.pdf") is None
    assert (
        await fetch_article(
            _fetcher(sbr_rules, lambda _: httpx.Response(404, text="x")),
            "https://news.example/a",
        )
        is None
    )
    assert (
        await fetch_article(
            _fetcher(sbr_rules, lambda _: httpx.Response(200, text=PARAGRAPH)),
            "http://internal.example/",
        )
        is None
    )
    assert (
        await fetch_article(
            _fetcher(sbr_rules, lambda _: httpx.Response(200)), "ftp://news.example/a"
        )
        is None
    )
