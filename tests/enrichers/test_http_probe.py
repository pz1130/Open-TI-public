import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from opti.core.config import ProjectRules
from opti.core.text_match import TextMatcher
from opti.enrichers.http_probe.enricher import MAX_BODY_BYTES, HttpProbeEnricher, page_features
from opti.sdk.http import HttpPolicy
from opti.sdk.testing import make_context

PHISH = """<html><head><title>Sample Brand &ndash; Secure Login</title>
<style>.x{}</style></head><body><form action="/p"><input name=u>
<input type="password" name=p></form><script>var a='SBR';</script></body></html>"""
PARKED = (
    "<html><head><title>sbr-loans.com is for sale</title></head><body>Buy this domain</body></html>"
)


def _handler(request: httpx.Request) -> httpx.Response:
    # 只认钉在已解析地址上的请求；按主机名直接 GET 视为未走检查过的地址。
    host = request.headers.get("host")
    if request.url.host == host:
        raise httpx.ConnectError("refused", request=request)
    scheme = request.url.scheme
    if scheme == "https" and host == "sbr-loans.com":
        return httpx.Response(200, html=PHISH)
    if scheme == "https" and host == "sbr-parked.com":
        return httpx.Response(200, html=PARKED)
    if scheme == "https" and host == "sbr-zip.com":
        return httpx.Response(
            200, content=b"PK\x03\x04", headers={"content-type": "application/zip"}
        )
    if scheme == "https" and host == "sbr-404.com":
        return httpx.Response(404, html="nope")
    if scheme == "http" and host == "sbr-http.com":
        return httpx.Response(200, html=PARKED)
    raise httpx.ConnectError("refused", request=request)


@pytest.fixture
def probe(sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch) -> HttpProbeEnricher:
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["1.2.3.4"]

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    ctx = make_context(
        sbr_rules, connector_id="http_probe", handler=_handler, policy=HttpPolicy(max_retries=0)
    )
    # 开关只跳过 is_global；仍解析并钉住 1.2.3.4，页面用例因此能打到 Mock。
    return HttpProbeEnricher(ctx, {"allow_private_targets": True})


def test_page_features(sbr_rules: ProjectRules) -> None:
    f = page_features(PHISH, TextMatcher(sbr_rules))
    assert f["title"] == "Sample Brand – Secure Login"
    assert f["has_form"] and f["has_password_field"]
    assert f["brand_terms"] == ["Sample Brand"]
    assert len(f["html_sha256"]) == 64


async def test_phishing_page(probe: HttpProbeEnricher) -> None:
    out = await probe.enrich("domain", "sbr-loans.com")
    assert out["reachable"] and out["status"] == 200 and out["has_password_field"]
    assert out["brand_terms"] == ["Sample Brand"]


async def test_parked_page(probe: HttpProbeEnricher) -> None:
    out = await probe.enrich("domain", "sbr-parked.com")
    assert out["title"] == "sbr-loans.com is for sale"
    assert out["brand_terms"] == [] and not out["has_password_field"]


async def test_non_html_is_not_parsed(probe: HttpProbeEnricher) -> None:
    out = await probe.enrich("domain", "sbr-zip.com")
    assert out["content_type"] == "application/zip" and "title" not in out


async def test_http_error_status_is_reachable(probe: HttpProbeEnricher) -> None:
    assert await probe.enrich("domain", "sbr-404.com") == {
        "reachable": True,
        "url": "https://sbr-404.com/",
        "status": 404,
    }


async def test_falls_back_to_http(probe: HttpProbeEnricher) -> None:
    out = await probe.enrich("domain", "sbr-http.com")
    assert out["url"] == "http://sbr-http.com/" and out["status"] == 200


async def test_unreachable(probe: HttpProbeEnricher) -> None:
    out = await probe.enrich("domain", "sbr-down.com")
    assert out["reachable"] is False and out["error"]


def _probe(
    sbr_rules: ProjectRules,
    handler: Callable[[httpx.Request], httpx.Response],
    config: dict[str, object] | None = None,
) -> HttpProbeEnricher:
    ctx = make_context(
        sbr_rules,
        connector_id="http_probe",
        handler=handler,
        policy=HttpPolicy(max_retries=0),
    )
    return HttpProbeEnricher(ctx, {} if config is None else config)


@pytest.mark.parametrize("target", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "localhost"])
async def test_non_public_targets_are_blocked_by_default(
    sbr_rules: ProjectRules, target: str
) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, html="x")

    out = await _probe(sbr_rules, handler).enrich("domain", target)
    assert out == {"reachable": False, "error": "blocked_non_public_address"}
    assert called is False


async def test_mixed_public_and_private_addresses_are_blocked(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    async def fake_resolve(host: str, port: int) -> list[str]:
        assert (host, port) == ("sbr-loans.com", 443)
        return ["1.2.3.4", "10.1.2.3"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, html="x")

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert out == {"reachable": False, "error": "blocked_non_public_address"}
    assert called is False


async def test_connects_to_checked_address(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[httpx.Request] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        assert host == "sbr-loans.com"
        assert port == 443
        return ["1.2.3.4", "8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, html=PHISH, headers={"content-type": "text/html"})

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert out["reachable"] is True and out["status"] == 200
    assert out["url"] == "https://sbr-loans.com/"
    assert len(seen) == 1
    assert seen[0].url.host == "1.2.3.4"
    assert seen[0].headers["host"] == "sbr-loans.com"
    assert seen[0].extensions["sni_hostname"] == "sbr-loans.com"


async def test_redirect_to_non_public_is_blocked(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_resolve(host: str, port: int) -> list[str]:
        if host == "sbr-loans.com":
            return ["1.2.3.4"]
        return ["127.0.0.1"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "1.2.3.4":
            return httpx.Response(302, headers={"location": "http://127.0.0.1/secret"})
        raise AssertionError(f"不应连接未检查或非公网地址：{request.url}")

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert out == {"reachable": False, "error": "blocked_non_public_address"}


async def test_redirect_rechecks_and_pins_next_hop(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_resolve(host: str, port: int) -> list[str]:
        return {"sbr-loans.com": ["1.2.3.4"], "sbr-parked.com": ["8.8.4.4"]}[host]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "1.2.3.4":
            return httpx.Response(302, headers={"location": "https://sbr-parked.com/login"})
        if request.url.host == "8.8.4.4":
            assert request.headers["host"] == "sbr-parked.com"
            assert request.extensions["sni_hostname"] == "sbr-parked.com"
            assert request.url.path == "/login"
            return httpx.Response(200, html=PARKED, headers={"content-type": "text/html"})
        raise AssertionError(str(request.url))

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert out["url"] == "https://sbr-loans.com/"
    assert out["final_url"] == "https://sbr-parked.com/login"
    assert out["redirects"] == ["https://sbr-loans.com/"]
    assert out["title"] == "sbr-loans.com is for sale"


async def test_allow_private_still_pins_and_rechecks_redirects(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved: list[tuple[str, int]] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        resolved.append((host, port))
        if host == "sbr-loans.com":
            return ["10.1.2.3"]
        if host == "169.254.169.254":
            return ["169.254.169.254"]
        raise AssertionError(host)

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "10.1.2.3":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})
        if request.url.host == "169.254.169.254":
            return httpx.Response(200, text="meta", headers={"content-type": "text/plain"})
        return httpx.Response(200, text="hostname")

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler, {"allow_private_targets": True}).enrich(
        "domain", "sbr-loans.com"
    )
    assert out["reachable"] is True and out["status"] == 200
    assert out["final_url"] == "http://169.254.169.254/latest"
    assert [r.url.host for r in seen] == ["10.1.2.3", "169.254.169.254"]
    assert resolved == [("sbr-loans.com", 443), ("169.254.169.254", 80)]
    assert seen[0].headers["host"] == "sbr-loans.com"
    assert seen[0].extensions["sni_hostname"] == "sbr-loans.com"
    assert seen[1].headers["host"] == "169.254.169.254"


async def test_probe_request_is_not_kept_alive(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[httpx.Request] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        assert host == "sbr-loans.com"
        return ["1.2.3.4"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, html=PHISH, headers={"content-type": "text/html"})

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert out["reachable"] is True and out["status"] == 200
    assert seen[0].url.host == "1.2.3.4"
    assert seen[0].headers["host"] == "sbr-loans.com"
    assert seen[0].extensions["sni_hostname"] == "sbr-loans.com"
    assert seen[0].headers["connection"] == "close"


async def test_probe_uses_configured_timeout_and_does_not_retry_5xx(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[httpx.Request] = []
    timeouts: list[object] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503)

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    ctx = make_context(
        sbr_rules,
        connector_id="http_probe",
        handler=handler,
        policy=HttpPolicy(max_retries=3, timeout=30.0),
    )
    client = ctx.http()._client
    original = client.stream

    def spy(method: str, url: str, **kwargs: Any) -> Any:
        timeouts.append(kwargs.get("timeout"))
        return original(method, url, **kwargs)

    monkeypatch.setattr(client, "stream", spy)
    out = await HttpProbeEnricher(ctx, {"timeout": 2.5}).enrich("domain", "sbr-loans.com")
    assert out == {"reachable": True, "url": "https://sbr-loans.com/", "status": 503}
    assert timeouts == [2.5]
    assert len(calls) == 1
    assert calls[0].url.host == "8.8.8.8"


async def test_punycode_host_and_sni_are_ascii(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[httpx.Request] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["1.2.3.4"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, html=PARKED, headers={"content-type": "text/html"})

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("domain", "xn--mller-kva.de")
    assert out["reachable"] is True and out["status"] == 200
    assert seen[0].url.host == "1.2.3.4"
    assert seen[0].headers["host"] == "xn--mller-kva.de"
    assert seen[0].extensions["sni_hostname"] == "xn--mller-kva.de"


async def test_slow_site_is_cut_off_by_total_timeout(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["8.8.8.8"]

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        return httpx.Response(200)

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    ctx = make_context(sbr_rules, connector_id="http_probe", handler=handler)
    probe = HttpProbeEnricher(ctx, {"timeout": 10, "total_timeout": 0.2})
    out = await asyncio.wait_for(probe.enrich("domain", "sbr-loans.com"), 5)
    assert out == {"reachable": False, "error": "TimeoutError"}


async def test_huge_page_is_truncated_not_buffered(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    pulled: list[int] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        async def body():  # type: ignore[no-untyped-def]
            yield b"<html><title>SBR Login</title><input type=password>"
            while True:
                pulled.append(1)
                yield b" " * 65536

        return httpx.Response(200, headers={"content-type": "text/html"}, content=body())

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    ctx = make_context(sbr_rules, connector_id="http_probe", handler=handler)
    out = await HttpProbeEnricher(ctx, {}).enrich("domain", "sbr-loans.com")
    assert out["status"] == 200 and out["has_password_field"] is True
    assert len(pulled) <= MAX_BODY_BYTES // 65536 + 1


async def test_probe_exact_url(sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, str, str | None]] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.url.raw_path.decode(), request.headers.get("host")))
        return httpx.Response(200, html=PHISH)

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich(
        "url", "https://sites.google.com/view/sbr-grants?id=7"
    )
    assert out["status"] == 200 and out["has_password_field"] is True
    assert out["url"] == "https://sites.google.com/view/sbr-grants?id=7"
    assert seen == [("8.8.8.8", "/view/sbr-grants?id=7", "sites.google.com")]


async def test_probe_url_with_unicode_host_and_no_scheme_fallback(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts: list[str | None] = []

    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.headers.get("host"))
        raise httpx.ConnectError("refused", request=request)

    monkeypatch.setattr("opti.enrichers.http_probe.enricher.resolve_addresses", fake_resolve)
    out = await _probe(sbr_rules, handler).enrich("url", "https://ѕbr-loans.com/login")
    assert out["reachable"] is False
    assert hosts == ["xn--br-loans-jhh.com"]  # 只试给定的 https，不回退 http


async def test_probe_url_to_private_address_is_blocked(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("不应发出请求")

    out = await _probe(sbr_rules, handler).enrich("url", "http://169.254.169.254/latest/meta-data/")
    assert out == {"reachable": False, "error": "blocked_non_public_address"}


async def test_probe_rejects_non_http_url(sbr_rules: ProjectRules) -> None:
    out = await _probe(sbr_rules, lambda _r: httpx.Response(200)).enrich(
        "url", "ftp://sbr-loans.com/x"
    )
    assert out == {"reachable": False, "error": "invalid_url"}
