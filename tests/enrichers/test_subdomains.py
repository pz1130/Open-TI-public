import json

import httpx
import pytest

from opti.core.config import ProjectRules
from opti.enrichers.subdomains import enricher as mod
from opti.sdk.testing import make_context


async def test_discovery_scopes_deduplicates_and_ignores_ct_expiry(sbr_rules: ProjectRules) -> None:
    async def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "crt.sh"
        assert request.url.params["q"] == "%.example.com"
        assert "exclude" not in request.url.params  # 已过期历史证书也可用于发现域名
        return httpx.Response(
            200,
            json=[
                {
                    "name_value": "www.example.com\nWWW.EXAMPLE.COM\n*.example.com\n*.only.example.com\nexample.com.evil.org\nnotexample.com",
                    "not_after": "2000-01-01",
                },
                {"common_name": "api.example.com", "name_value": "xn--fsqu00a.example.com"},
                {"name_value": "bad_name.example.com"},
            ],
        )

    ctx = make_context(sbr_rules, connector_id="subdomains", handler=respond)
    try:
        result = await mod.SubdomainsEnricher(ctx, {}).enrich("domain", "example.com")
        assert result == {
            "domains": [
                "api.example.com",
                "example.com",
                "www.example.com",
                "xn--fsqu00a.example.com",
            ],
            "source": "crt.sh",
            "truncated": False,
        }
    finally:
        await ctx.http().aclose()


@pytest.mark.parametrize("body", [{"error": "timeout"}, None])
async def test_invalid_response_reports_failure(sbr_rules: ProjectRules, body: object) -> None:
    ctx = make_context(
        sbr_rules,
        connector_id="subdomains",
        handler=lambda _: httpx.Response(200, content=json.dumps(body)),
    )
    try:
        assert (await mod.SubdomainsEnricher(ctx, {}).enrich("domain", "example.com"))[
            "error"
        ] == "invalid_ct_response"
    finally:
        await ctx.http().aclose()


async def test_discovery_cap_is_visible(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "MAX_DOMAINS", 2)
    ctx = make_context(
        sbr_rules,
        connector_id="subdomains",
        handler=lambda _: httpx.Response(
            200, json=[{"name_value": "a.example.com\nb.example.com"}]
        ),
    )
    try:
        result = await mod.SubdomainsEnricher(ctx, {}).enrich("domain", "example.com")
        assert len(result["domains"]) == 2 and result["truncated"] is True
    finally:
        await ctx.http().aclose()
