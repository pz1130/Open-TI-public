import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Entity, Finding
from opti.enrichers.pulsedive.enricher import (
    PulsediveEnricher,
    parse_indicator,
    public_indicator,
)
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.context import EnvSecretProvider
from opti.sdk.models import RawItem, utcnow
from opti.sdk.registry import Registry, gate, load_instance_config
from opti.sdk.testing import make_context, static_enricher


def _ctx(rules: ProjectRules, handler: Any) -> Any:
    return make_context(
        rules, connector_id="pulsedive", handler=handler,
        secrets=EnvSecretProvider({"OPTI_SECRET_PULSEDIVE_API_KEY": "test-secret-key"}),
    )  # fmt: skip


def _body(indicator: str = "sbr-loans.com", type_: str = "domain") -> dict[str, Any]:
    return {
        "indicator": indicator,
        "type": type_,
        "risk": "high",
        "risk_recommended": "medium",
        "manualrisk": 1,
        "retired": 0,
        "stamp_seen": "2026-10-04 10:00:00",
        "comments": [{"username": "reporter", "comment": "sensitive"}],
        "properties": {"whois": {"++email": "person@example.org"}},
        "cookies": {"session": "secret"},
    }


def test_manifest_requires_commercial_plan_and_approval() -> None:
    manifest = Registry().manifest("pulsedive")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.tier.value == "paid"
    assert set(manifest.plans) == {"team", "business"}
    assert not instance.enabled and not instance.license_approved and instance.plan == "team"
    assert not gate(manifest, instance, EnvSecretProvider({})).runnable


def test_only_minimal_matching_fields_are_parsed() -> None:
    assert parse_indicator(_body(), "domain", "sbr-loans.com") == {
        "found": True,
        "risk": "high",
        "risk_recommended": "medium",
        "manual_override": True,
        "retired": False,
        "last_seen_utc": "2026-10-04 10:00:00",
    }
    assert (
        parse_indicator(_body("2001:4860:4860::8888", "ip"), "ip", "2001:4860:4860::8888")["risk"]
        == "high"
    )
    for bad in (
        _body("elsewhere.com"),
        {**_body(), "risk": ["high"]},
        {**_body(), "manualrisk": True},
        {**_body(), "stamp_seen": "yesterday"},
        {**_body(), "type": "url"},
    ):
        with pytest.raises(ValueError):
            parse_indicator(bad, "domain", "sbr-loans.com")


def test_public_indicator_blocks_non_public_and_malformed_values() -> None:
    assert public_indicator("domain", "SBR-Loans.COM.") == "sbr-loans.com"
    assert public_indicator("ip", "2001:4860:4860:0:0:0:0:8888") == "2001:4860:4860::8888"
    for type_, value in (
        ("domain", "server.internal"),
        ("domain", "localhost"),
        ("domain", "bad_name.com"),
        ("domain", "https://sbr-loans.com/secret"),
        ("ip", "10.0.0.1"),
        ("ip", "::1"),
        ("ip", "2001:4860:4860::8888%eth0"),
        ("ip", "bad"),
        ("url", "https://sbr-loans.com/?token=secret"),
    ):
        assert public_indicator(type_, value) is None


async def test_only_read_only_lookup_and_key_is_redacted(
    sbr_rules: ProjectRules, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_body())

    enricher = PulsediveEnricher(_ctx(sbr_rules, handler), {})
    with caplog.at_level(logging.INFO, logger="httpx"):
        result = await enricher.enrich("domain", "SBR-Loans.COM.")
    assert result["risk"] == "high" and "comments" not in result
    assert len(calls) == 1 and calls[0].method == "GET"
    assert calls[0].url.path == "/api/indicator.php"
    assert dict(calls[0].url.params) == {
        "indicator": "sbr-loans.com",
        "historical": "0",
        "schema": "0",
        "key": "test-secret-key",
    }
    assert "test-secret-key" not in caplog.text
    assert "test-secret-key" not in repr(result)
    assert await enricher.enrich("url", "https://sbr-loans.com/") == {"error": "unsupported_type"}
    assert len(calls) == 1


async def test_not_found_is_unknown_and_429_cools_down(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def missing(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404, json={"error": "Indicator not found"})

    assert await PulsediveEnricher(_ctx(sbr_rules, missing), {}).enrich("ip", "8.8.8.8") == {
        "found": False
    }
    assert len(calls) == 1
    calls.clear()

    def limited(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429)

    enricher = PulsediveEnricher(_ctx(sbr_rules, limited), {})
    assert await enricher.enrich("ip", "8.8.8.8") == {"error": "rate_limited"}
    assert await enricher.enrich("ip", "1.1.1.1") == {"error": "rate_limited"}
    assert len(calls) == 1


async def test_redirect_and_invalid_response_are_rejected(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://elsewhere.example/"})

    assert await PulsediveEnricher(_ctx(sbr_rules, redirect), {}).enrich("ip", "8.8.8.8") == {
        "error": "http_302"
    }
    assert len(calls) == 1

    def malformed(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"indicator": "8.8.8.8", "type": "ip"})

    assert await PulsediveEnricher(_ctx(sbr_rules, malformed), {}).enrich("ip", "8.8.8.8") == {
        "error": "invalid_response"
    }


@pytest.mark.db
async def test_ip_reputation_remains_context_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ctx = make_context(sbr_rules)
    context = {"found": True, "risk": "critical", "retired": False}
    enricher = static_enricher(ctx, "pulsedive", context, types=("ip",))
    processor = Processor(
        sbr_rules, EnrichmentService({"pulsedive": enricher}), enrich_ids=("pulsedive",)
    )
    item = RawItem(
        "dmarc", "pulsedive-ip", utcnow(), None,
        {"indicators": [{"type": "ip", "value": "45.33.32.156", "volume": 140}],
         "signal": "dmarc_fail", "context": {}},
        project_ids=(sbr_rules.project,),
    )  # fmt: skip
    result = await processor.process(session, item)
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.score == 75
    assert "pulsedive" not in finding.score_breakdown
    entity = await session.get(Entity, finding.entity_id)
    assert entity is not None and entity.enrichment["pulsedive"]["data"] == context


@pytest.mark.db
async def test_domain_reputation_remains_context_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ctx = make_context(sbr_rules)
    context = {"found": True, "risk": "critical", "retired": False}
    enricher = static_enricher(ctx, "pulsedive", context, types=("domain",))
    processor = Processor(
        sbr_rules, EnrichmentService({"pulsedive": enricher}), enrich_ids=("pulsedive",)
    )
    item = RawItem(
        "report_mailbox", "pulsedive-domain", utcnow(), None,
        {"indicators": [{"type": "domain", "value": "sbr-loans.com"}],
         "signal": "reported", "context": {}},
        project_ids=(sbr_rules.project,),
    )  # fmt: skip
    result = await processor.process(session, item)
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and "pulsedive" not in finding.score_breakdown
    entity = await session.get(Entity, finding.entity_id)
    assert entity is not None and entity.enrichment["pulsedive"]["data"] == context
