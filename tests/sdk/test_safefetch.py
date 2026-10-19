from typing import Any

import httpx
import pytest

from opti.core.config import ProjectRules
from opti.sdk.safefetch import FetchError, SafeFetcher, ascii_url
from opti.sdk.testing import make_context

ADDRS = {
    "news.example": ["93.184.216.34"],
    "internal.example": ["10.0.0.5"],
    "meta.example": ["169.254.169.254"],
}


@pytest.mark.parametrize(
    "url",
    ["http://[bad", "https://user:pass@news.example/a", "http://%5bbad/a", "ftp://news.example/a"],
)
def test_ascii_url_rejects_malformed_or_credential_urls(url: str) -> None:
    assert ascii_url(url) is None


async def _resolve(host: str, port: int) -> list[str]:
    return ADDRS.get(host, [])


def _fetcher(rules: ProjectRules, handler: Any) -> SafeFetcher:
    return SafeFetcher(make_context(rules, handler=handler).http(), resolve=_resolve)


async def test_fetches_public_pages_with_pinned_address(sbr_rules: ProjectRules) -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers["host"]))
        return httpx.Response(200, text="<html><title>ok</title></html>")

    response, final, redirects = await _fetcher(sbr_rules, handler).open(
        "https://news.example/a?b=1"
    )
    assert response.status_code == 200 and final == "https://news.example/a?b=1"
    assert redirects == []
    assert seen == [("https://93.184.216.34/a?b=1", "news.example")]


@pytest.mark.parametrize(
    "url",
    [
        "http://internal.example/",
        "http://meta.example/latest/meta-data/",
        "http://nowhere.example/",
    ],
)
async def test_blocks_non_public_targets(sbr_rules: ProjectRules, url: str) -> None:
    with pytest.raises(FetchError) as error:
        await _fetcher(sbr_rules, lambda _: httpx.Response(200)).open(url)
    assert error.value.blocked


async def test_redirect_to_private_is_blocked(sbr_rules: ProjectRules) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://internal.example/admin"})

    with pytest.raises(FetchError) as error:
        await _fetcher(sbr_rules, handler).open("https://news.example/r")
    assert error.value.blocked


async def test_redirect_with_credentials_is_blocked(sbr_rules: ProjectRules) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["host"])
        return httpx.Response(
            302, headers={"location": "https://user:password@news.example/private"}
        )

    with pytest.raises(FetchError) as error:
        await _fetcher(sbr_rules, handler).open("https://news.example/start")
    assert error.value.blocked and seen == ["news.example"]


async def test_literal_private_address_is_blocked_before_dns(sbr_rules: ProjectRules) -> None:
    calls: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        calls.append(host)
        return ["93.184.216.34"]

    fetcher = SafeFetcher(
        make_context(sbr_rules, handler=lambda _: httpx.Response(200)).http(), resolve=resolve
    )
    with pytest.raises(FetchError) as error:
        await fetcher.open("http://127.0.0.1/private")
    assert error.value.blocked and calls == []


async def test_too_many_redirects(sbr_rules: ProjectRules) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/again"})

    with pytest.raises(FetchError):
        await _fetcher(sbr_rules, handler).open("https://news.example/r")
