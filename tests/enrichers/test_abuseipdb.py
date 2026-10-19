from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Entity, Finding
from opti.enrichers.abuseipdb.enricher import AbuseIpdbEnricher, parse_check
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.context import EnvSecretProvider
from opti.sdk.models import RawItem, utcnow
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context, static_enricher


def _ctx(rules: ProjectRules, handler: Any) -> Any:
    return make_context(
        rules, connector_id="abuseipdb", handler=handler,
        secrets=EnvSecretProvider({"OPTI_SECRET_ABUSEIPDB_API_KEY": "test-key"}),
    )  # fmt: skip


def _body(ip: str = "8.8.8.8", score: Any = 92) -> dict[str, Any]:
    return {"data": {
        "ipAddress": ip, "isPublic": True, "abuseConfidenceScore": score,
        "totalReports": 12, "isWhitelisted": False,
        "lastReportedAt": "2026-10-04T10:00:00+00:00",
        "reports": [{"comment": "sensitive log", "reporterId": 123}],
        "hostnames": ["user.example"],
    }}  # fmt: skip


def test_manifest_requires_paid_plan_and_parser_discards_reports() -> None:
    manifest = Registry().manifest("abuseipdb")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.tier.value == "paid" and set(manifest.plans) == {"basic"}
    assert not instance.enabled and not instance.license_approved and instance.plan == "basic"
    assert parse_check(_body(), "8.8.8.8") == {
        "abuse_confidence": 92, "total_reports": 12, "is_whitelisted": False,
        "last_reported_at": "2026-10-04T10:00:00+00:00", "max_age_days": 90,
    }  # fmt: skip
    assert (
        parse_check(_body(ip="2001:4860:4860::8888"), "2001:4860:4860::8888")["abuse_confidence"]
        == 92
    )
    for bad in (_body(ip="1.1.1.1"), _body(score=True), _body(score=101)):
        with pytest.raises(ValueError):
            parse_check(bad, "8.8.8.8")


async def test_only_public_ip_uses_read_only_check_without_verbose(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_body())

    enricher = AbuseIpdbEnricher(_ctx(sbr_rules, handler), {})
    for value in ("10.0.0.1", "127.0.0.1", "::1", "bad"):
        assert (await enricher.enrich("ip", value)).get("abuse_confidence") is None
    assert await enricher.enrich("domain", "8.8.8.8") == {"error": "unsupported_type"}
    assert not calls
    result = await enricher.enrich("ip", "8.8.8.8")
    assert result["abuse_confidence"] == 92 and "reports" not in result
    assert len(calls) == 1 and calls[0].method == "GET"
    assert (
        str(calls[0].url)
        == "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90"
    )
    assert (
        calls[0].headers["key"] == "test-key" and calls[0].headers["accept"] == "application/json"
    )
    assert "verbose" not in calls[0].url.params


async def test_429_cools_down_and_redirect_is_not_followed(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def limited(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429)

    enricher = AbuseIpdbEnricher(_ctx(sbr_rules, limited), {})
    assert await enricher.enrich("ip", "8.8.8.8") == {"error": "rate_limited"}
    assert await enricher.enrich("ip", "1.1.1.1") == {"error": "rate_limited"}
    assert len(calls) == 1

    calls.clear()

    def redirect(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://elsewhere.example/"})

    assert await AbuseIpdbEnricher(_ctx(sbr_rules, redirect), {}).enrich("ip", "8.8.8.8") == {
        "error": "http_302"
    }
    assert len(calls) == 1


async def test_malformed_response_is_not_cached(sbr_rules: ProjectRules) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"ipAddress": "8.8.8.8"}})

    enricher = AbuseIpdbEnricher(_ctx(sbr_rules, handler), {})
    assert await enricher.enrich("ip", "8.8.8.8") == {"error": "invalid_response"}
    assert calls == 1


@pytest.mark.db
async def test_ip_reputation_stays_context_only(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ctx = make_context(sbr_rules)
    context = {"abuse_confidence": 99, "total_reports": 100, "is_whitelisted": False}
    enricher = static_enricher(ctx, "abuseipdb", context, types=("ip",))
    processor = Processor(
        sbr_rules, EnrichmentService({"abuseipdb": enricher}), enrich_ids=("abuseipdb",)
    )
    item = RawItem(
        "dmarc", "abuseipdb-ip", utcnow(), None,
        {"indicators": [{"type": "ip", "value": "45.33.32.156", "volume": 140}],
         "signal": "dmarc_fail", "context": {}},
        project_ids=(sbr_rules.project,),
    )  # fmt: skip
    result = await processor.process(session, item)
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.score == 75
    assert "abuseipdb" not in finding.score_breakdown
    entity = await session.get(Entity, finding.entity_id)
    assert entity is not None and entity.enrichment["abuseipdb"]["data"] == context
