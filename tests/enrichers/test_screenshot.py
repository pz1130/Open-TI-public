import base64
import json

import httpx
import pytest

from opti.core.config import ProjectRules
from opti.enrichers.screenshot.enricher import ScreenshotEnricher
from opti.sdk.manifest import ManifestError, validate_instance_config
from opti.sdk.registry import Registry
from opti.sdk.testing import make_context

OK = {
    "url": "https://sbr-loans.com/", "final_url": "https://sbr-loans.com/login", "status": 200,
    "title": "SBR Login", "redirects": ["https://sbr-loans.com/"], "blocked": [],
    "browser": "chromium 140.0", "captured_at": "2026-10-02T08:00:00+00:00",
    "screenshot_b64": "iVBORw0KGgo=", "html_b64": "PGh0bWw+",
}  # fmt: skip


def _enricher(rules: ProjectRules, handler):  # type: ignore[no-untyped-def]
    ctx = make_context(rules, handler=handler, connector_id="screenshot")
    return ScreenshotEnricher(ctx, {"sandbox_url": "http://browser:8000", "timeout": 20})


async def test_returns_artifacts_and_method(sbr_rules: ProjectRules) -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST" and str(request.url) == "http://browser:8000/capture"
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=OK)

    out = await _enricher(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert seen == [{"url": "https://sbr-loans.com/", "timeout": 20.0}]
    assert out["final_url"] == "https://sbr-loans.com/login" and out["status"] == 200
    assert out["method"].startswith("opti-sandbox/") and "chromium 140.0" in out["method"]
    assert [(a["name"], a["content_type"]) for a in out["artifacts"]] == [
        ("screenshot", "image/png"), ("html", "text/html"),
    ]  # fmt: skip


async def test_rendered_body_exposes_sale_page_even_when_original_shell_is_empty(
    sbr_rules: ProjectRules,
) -> None:
    data = {
        **OK,
        "title": "Welcome",
        "page_text": "Buy this domain",
        "html_b64": base64.b64encode(
            b"<html><head><title>Welcome</title></head><body><form><input type=password></form></body></html>"
        ).decode(),
        "content_type": "text/html",
    }
    out = await _enricher(sbr_rules, lambda _: httpx.Response(200, json=data)).enrich(
        "domain", "sbr.example"
    )
    assert out["text_excerpt"] == "Buy this domain" and out["parking_signals"] == [
        "buy this domain"
    ]
    assert out["has_form"] and out["has_password_field"] and out["content_type"] == "text/html"


async def test_falls_back_to_http(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = json.loads(request.content)["url"]
        if url.startswith("https://"):
            return httpx.Response(
                200, json={"url": url, "error": "navigation: net::ERR_SSL_PROTOCOL_ERROR"}
            )
        return httpx.Response(200, json={**OK, "url": url, "final_url": url})

    out = await _enricher(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert out["final_url"] == "http://sbr-loans.com/"


async def test_blocked_target_reports_error(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = json.loads(request.content)["url"]
        return httpx.Response(
            200,
            json={"url": url, "error": "navigation: net::ERR_BLOCKED_BY_CLIENT", "blocked": [url]},
        )

    out = await _enricher(sbr_rules, handler).enrich("domain", "sbr-loans.com")
    assert "ERR_BLOCKED_BY_CLIENT" in out["error"] and "artifacts" not in out


async def test_sandbox_unavailable(sbr_rules: ProjectRules) -> None:
    out = await _enricher(sbr_rules, lambda _r: httpx.Response(502)).enrich(
        "domain", "sbr-loans.com"
    )
    assert out["error"].startswith("sandbox_unavailable")


async def test_punycode_host(sbr_rules: ProjectRules) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["url"])
        return httpx.Response(200, json=OK)

    await _enricher(sbr_rules, handler).enrich("domain", "sbr-貸款.com")
    assert seen[0].startswith("https://xn--")


async def test_url_entity_captures_exact_url(sbr_rules: ProjectRules) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = json.loads(request.content)["url"]
        seen.append(url)
        return httpx.Response(
            200, json={"url": url, "error": "navigation: net::ERR_CONNECTION_REFUSED"}
        )

    out = await _enricher(sbr_rules, handler).enrich("url", "https://ѕbr-loans.com/login?x=1")
    assert seen == ["https://xn--br-loans-jhh.com/login?x=1"]  # 只截这一个 URL，不回退 http
    assert "ERR_CONNECTION_REFUSED" in out["error"]


async def test_logo_similarity_is_context_only(sbr_rules: ProjectRules) -> None:
    reference = "0f0f0f0f0f0f0f0f"
    box = {"x": 20, "y": 10, "width": 80, "height": 60}
    ctx = make_context(
        sbr_rules,
        handler=lambda _r: httpx.Response(
            200,
            json={
                **OK,
                "visual_candidates": [
                    {"dhash64": reference, "box": box},
                    {"dhash64": "0000000000000000", "box": box},
                ],
            },
        ),
        connector_id="screenshot",
    )
    enricher = ScreenshotEnricher(
        ctx,
        {
            "sandbox_url": "http://browser:8000",
            "logo_hashes": [{"name": "official", "dhash64": reference}],
        },
    )
    out = await enricher.enrich("domain", "sbr-loans.com")
    assert out["visual"] == {
        "method": "dhash64",
        "threshold": 8,
        "candidate_count": 1,
        "possible_matches": [{"reference": "official", "distance": 0, "box": box}],
    }
    assert "visual_candidates" not in out


async def test_favicon_fingerprint_and_exact_reference_match(sbr_rules: ProjectRules) -> None:
    icon = {
        "url": "https://sbr-loans.com/icon.png",
        "mmh3": -123456,
        "sha256": "a" * 64,
        "size_bytes": 1024,
    }
    ctx = make_context(
        sbr_rules,
        handler=lambda _r: httpx.Response(200, json={**OK, "favicon": icon}),
        connector_id="screenshot",
    )
    enricher = ScreenshotEnricher(
        ctx,
        {
            "sandbox_url": "http://browser:8000",
            "favicon_hashes": [{"name": "机构官网", "mmh3": -123456}],
        },
    )
    out = await enricher.enrich("domain", "sbr-loans.com")
    assert out["favicon"] == {
        "method": "mmh3-rfc2045-base64",
        "hash": -123456,
        "sha256": "a" * 64,
        "size_bytes": 1024,
        "url": icon["url"],
        "reference_matches": ["机构官网"],
    }
    assert "artifacts" in out and "visual" not in out


async def test_ocr_persists_only_brand_terms_not_raw_text(sbr_rules: ProjectRules) -> None:
    source_text = "Sample Brand 样 本 品牌 private account 123456"
    ctx = make_context(
        sbr_rules,
        handler=lambda _r: httpx.Response(200, json={**OK, "ocr_text": source_text}),
        connector_id="screenshot",
    )
    out = await ScreenshotEnricher(ctx, {"sandbox_url": "http://browser:8000"}).enrich(
        "domain", "sbr-loans.com"
    )
    assert out["ocr"] == {
        "method": "tesseract-eng+chi_sim-psm11",
        "char_count": len(source_text),
        "brand_terms": ["Sample Brand", "样本品牌"],
    }
    assert "ocr_text" not in out and "private account" not in str(out)


def test_logo_reference_config_requires_named_64_bit_hash() -> None:
    manifest = Registry().manifest("screenshot")
    assert validate_instance_config(manifest, {})["logo_hashes"] == []
    for references in ([{"name": "org", "dhash64": "bad"}], [{"dhash64": "0" * 16}]):
        with pytest.raises(ManifestError):
            validate_instance_config(manifest, {"logo_hashes": references})


def test_favicon_reference_config_requires_signed_32_bit_hash() -> None:
    manifest = Registry().manifest("screenshot")
    assert validate_instance_config(manifest, {})["favicon_hashes"] == []
    for references in ([{"name": "org", "mmh3": 2**31}], [{"name": "org", "mmh3": True}]):
        with pytest.raises(ManifestError):
            validate_instance_config(manifest, {"favicon_hashes": references})
