import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Finding
from opti.enrichers.botnet_feed import enricher as module
from opti.enrichers.botnet_feed.enricher import (
    BotnetFeedEnricher,
    feodo_entries,
    sslbl_entries,
)
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem, utcnow
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context, static_enricher


def test_manifest_and_feed_parsers() -> None:
    manifest = Registry().manifest("botnet_feed")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert (
        manifest.category == "enrichment" and not instance.enabled and not instance.license_approved
    )
    parsed = feodo_entries(
        [
            {"ip_address": "8.8.8.8", "port": 443, "malware": "QakBot"},
            {"ip_address": "10.0.0.1", "port": 443, "malware": "private"},
            {"ip_address": "8.8.8.8", "port": 0, "malware": "bad-port"},
            {"ip_address": "bad", "port": 443},
        ]
    )
    assert parsed == {"8.8.8.8": [{"ip": "8.8.8.8", "port": 443, "malware": "QakBot"}]}
    with pytest.raises(ValueError):
        feodo_entries({"bad": "shape"})
    assert sslbl_entries("# comment\n2026-10-04," + "A" * 40 + ",Malware C&C\ninvalid\n") == {
        "a" * 40: "Malware C&C"
    }


async def test_domain_correlation_pins_ip_and_caches_feeds(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[httpx.Request] = []
    certificate = b"fake-der-certificate"
    sha1 = hashlib.sha1(certificate, usedforsecurity=False).hexdigest()
    targets: list[tuple[str, str]] = []

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    async def certificate_for(
        address: str, _port: int, *, server_name: str, timeout: float
    ) -> bytes:
        targets.append((address, server_name))
        return certificate

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "feodotracker.abuse.ch":
            return httpx.Response(
                200, json=[{"ip_address": "8.8.8.8", "port": 443, "malware": "QakBot"}]
            )
        return httpx.Response(200, text=f"2026-10-04,{sha1},Malware C&C\n")

    monkeypatch.setattr(module, "resolve_addresses", resolve)
    monkeypatch.setattr(module, "fetch_certificate", certificate_for)
    enricher = BotnetFeedEnricher(make_context(sbr_rules, handler=handler), {})
    first = await enricher.enrich("domain", "sbr-loans.com")
    second = await enricher.enrich("domain", "sbr-loans.com")
    assert first == second
    assert first["feodo"] == [{"ip": "8.8.8.8", "port": 443, "malware": "QakBot"}]
    assert first["sslbl"] == {"sha1": sha1, "reason": "Malware C&C"}
    assert targets == [("8.8.8.8", "sbr-loans.com")] * 2
    assert [str(request.url) for request in requests] == [module.FEODO_URL, module.SSLBL_URL]
    assert all(request.method == "GET" for request in requests)


async def test_private_resolution_does_not_contact_feeds(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def resolve(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8", "10.0.0.1"]

    monkeypatch.setattr(module, "resolve_addresses", resolve)
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    data = await BotnetFeedEnricher(make_context(sbr_rules, handler=handler), {}).enrich(
        "domain", "sbr-loans.com"
    )
    assert data == {"lookup_error": "non_public_address"}
    assert not calls


async def test_feed_redirects_are_not_followed(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def resolve(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    monkeypatch.setattr(module, "resolve_addresses", resolve)
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example/feed"})

    data = await BotnetFeedEnricher(make_context(sbr_rules, handler=handler), {}).enrich(
        "domain", "sbr-loans.com"
    )
    assert data == {"feodo": [], "sslbl": None}
    assert [str(request.url) for request in calls] == [module.FEODO_URL, module.SSLBL_URL]


@pytest.mark.db
async def test_c2_match_is_context_without_automatic_score_boost(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    ctx = make_context(sbr_rules)
    context: dict[str, Any] = {
        "feodo": [{"ip": "8.8.8.8", "port": 443, "malware": "QakBot"}],
        "sslbl": None,
    }
    enricher = static_enricher(ctx, "botnet_feed", context)
    processor = Processor(
        sbr_rules, EnrichmentService({"botnet_feed": enricher}), enrich_ids=("botnet_feed",)
    )
    item = RawItem(
        "certstream",
        "c2-candidate",
        utcnow(),
        None,
        {"matches": [{"domain": "sbr-loans.com"}]},
        project_ids=(sbr_rules.project,),
    )
    result = await processor.process(session, item)
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None
    assert finding.match["botnet_context"] == context
    assert "botnet" not in finding.score_breakdown
