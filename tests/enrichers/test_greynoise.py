from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Entity, Finding
from opti.enrichers.greynoise.enricher import GreyNoiseEnricher, parse_community
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.context import EnvSecretProvider
from opti.sdk.models import RawItem, utcnow
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context, static_enricher


def _ctx(rules: ProjectRules, handler: Any) -> Any:
    return make_context(
        rules, connector_id="greynoise", handler=handler,
        secrets=EnvSecretProvider({"OPTI_SECRET_GREYNOISE_API_KEY": "test-key"}),
    )  # fmt: skip


def test_manifest_is_gated_and_parser_keeps_only_supported_fields() -> None:
    manifest = Registry().manifest("greynoise")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.kind == ("enricher",)
    assert manifest.commercial_use == "restricted"
    assert not instance.enabled and not instance.license_approved
    data = parse_community({
        "ip": "8.8.8.8", "noise": True, "riot": False, "classification": "malicious",
        "name": "  Test  Scanner ", "last_seen": "2026-10-04", "message": "untrusted",
        "link": "https://elsewhere.example", "raw_data": ["secret"],
    }, "8.8.8.8")  # fmt: skip
    assert data == {
        "found": True, "noise": True, "riot": False, "classification": "malicious",
        "name": "Test Scanner", "last_seen": "2026-10-04",
    }  # fmt: skip
    for bad in (
        {"ip": "1.1.1.1", "noise": True, "riot": False, "classification": "benign"},
        {"ip": "8.8.8.8", "noise": 1, "riot": False, "classification": "benign"},
        {"ip": "8.8.8.8", "noise": True, "riot": False, "classification": []},
    ):
        with pytest.raises(ValueError):
            parse_community(bad, "8.8.8.8")


async def test_only_public_ipv4_uses_fixed_community_endpoint(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "ip": "8.8.8.8",
                "noise": True,
                "riot": True,
                "classification": "unknown",
                "name": "Public DNS",
                "last_seen": "2026-10-04",
            },
        )

    enricher = GreyNoiseEnricher(_ctx(sbr_rules, handler), {})
    for value in ("10.0.0.1", "127.0.0.1", "2001:4860:4860::8888", "bad"):
        assert (await enricher.enrich("ip", value)).get("found") is not True
    assert await enricher.enrich("domain", "8.8.8.8") == {"error": "unsupported_type"}
    assert not calls
    result = await enricher.enrich("ip", "8.8.8.8")
    assert result["noise"] is True and result["riot"] is True
    assert len(calls) == 1
    assert str(calls[0].url) == "https://api.greynoise.io/v3/community/8.8.8.8"
    assert calls[0].method == "GET" and calls[0].headers["key"] == "test-key"


async def test_not_found_is_not_benign_and_failures_are_not_retried(
    sbr_rules: ProjectRules,
) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404)

    assert await GreyNoiseEnricher(_ctx(sbr_rules, handler), {}).enrich("ip", "8.8.8.8") == {
        "found": False,
        "noise": False,
        "riot": False,
    }
    assert len(calls) == 1

    calls.clear()

    def limited(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429)

    enricher = GreyNoiseEnricher(_ctx(sbr_rules, limited), {})
    assert await enricher.enrich("ip", "8.8.8.8") == {"error": "rate_limited"}
    assert await enricher.enrich("ip", "1.1.1.1") == {"error": "rate_limited"}
    assert len(calls) == 1


async def test_redirect_and_malformed_response_are_rejected(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://elsewhere.example/"})

    assert await GreyNoiseEnricher(_ctx(sbr_rules, redirect), {}).enrich("ip", "8.8.8.8") == {
        "error": "http_302"
    }
    assert len(calls) == 1
    bad = lambda _request: httpx.Response(200, json={"ip": "1.1.1.1"})  # noqa: E731
    assert await GreyNoiseEnricher(_ctx(sbr_rules, bad), {}).enrich("ip", "8.8.8.8") == {
        "error": "invalid_response"
    }


@pytest.mark.db
async def test_ip_signal_enrichment_is_context_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ctx = make_context(sbr_rules)
    result_data = {"found": True, "noise": True, "riot": False, "classification": "malicious"}
    enricher = static_enricher(ctx, "greynoise", result_data, types=("ip",))
    processor = Processor(
        sbr_rules, EnrichmentService({"greynoise": enricher}), enrich_ids=("greynoise",)
    )
    item = RawItem(
        "dmarc", "greynoise-ip", utcnow(), None,
        {"indicators": [{"type": "ip", "value": "45.33.32.156", "volume": 140}],
         "signal": "dmarc_fail", "context": {}},
        project_ids=(sbr_rules.project,),
    )  # fmt: skip
    result = await processor.process(session, item)
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.score == 75
    assert "greynoise" not in finding.score_breakdown
    entity = await session.get(Entity, finding.entity_id)
    assert entity is not None and entity.enrichment["greynoise"]["data"] == result_data
