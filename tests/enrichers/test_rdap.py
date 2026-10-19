from typing import Any

import httpx

from opti.core.config import ProjectRules
from opti.enrichers.rdap.enricher import BOOTSTRAP_URL, RdapEnricher, parse_bootstrap, parse_rdap
from opti.sdk.testing import make_context

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["http://rdap.verisign.example/com/v1/", "https://rdap.verisign.example/com/v1/"]],
        [["top"], ["https://rdap.nic.top/"]],
    ]
}  # fmt: skip

DOMAIN_DOC: dict[str, Any] = {
    "objectClassName": "domain",
    "ldhName": "SBR-LOANS.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "2026-09-25T10:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-09-25T10:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-09-26T08:00:00Z"},
    ],
    "nameservers": [{"ldhName": "NS2.HOST.EXAMPLE"}, {"ldhName": "NS1.HOST.EXAMPLE"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Cheap Registrar LLC"]]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]],
                }
            ],
        }
    ],
}  # fmt: skip


def test_parse_bootstrap_prefers_https() -> None:
    table = parse_bootstrap(BOOTSTRAP)
    assert table["com"] == "https://rdap.verisign.example/com/v1/"
    assert table["top"] == "https://rdap.nic.top/"


def test_parse_rdap_extracts_nested_abuse() -> None:
    out = parse_rdap(DOMAIN_DOC)
    assert out["registration"] == "2026-09-25T10:00:00Z"
    assert out["registrar"] == "Cheap Registrar LLC"
    assert out["abuse_email"] == "abuse@registrar.example"
    assert out["nameservers"] == ["ns1.host.example", "ns2.host.example"]


def test_parse_rdap_tolerates_missing_or_malformed_fields() -> None:
    out = parse_rdap(
        {"entities": [{"roles": ["registrar"], "vcardArray": "broken"}], "events": [1]}
    )
    assert out["registrar"] is None and out["registration"] is None and out["status"] == []


def _handler(domain_status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == BOOTSTRAP_URL:
            return httpx.Response(200, json=BOOTSTRAP)
        if url == "https://rdap.verisign.example/com/v1/domain/sbr-loans.com":
            return httpx.Response(domain_status, json=DOMAIN_DOC if domain_status == 200 else {})
        return httpx.Response(500)

    return handler


async def test_rdap_found(sbr_rules: ProjectRules) -> None:
    e = RdapEnricher(make_context(sbr_rules, connector_id="rdap", handler=_handler()), {})
    out = await e.enrich("domain", "www.sbr-loans.com")
    assert out["supported"] and out["found"] and out["registrar"] == "Cheap Registrar LLC"


async def test_rdap_not_found(sbr_rules: ProjectRules) -> None:
    e = RdapEnricher(make_context(sbr_rules, connector_id="rdap", handler=_handler(404)), {})
    assert await e.enrich("domain", "sbr-loans.com") == {"supported": True, "found": False}


async def test_rdap_rate_limited_is_reported_not_raised(sbr_rules: ProjectRules) -> None:
    e = RdapEnricher(make_context(sbr_rules, connector_id="rdap", handler=_handler(429)), {})
    out = await e.enrich("domain", "sbr-loans.com")
    assert out["found"] is None and out["error"] == "429"


async def test_rdap_unsupported_tld(sbr_rules: ProjectRules) -> None:
    e = RdapEnricher(make_context(sbr_rules, connector_id="rdap", handler=_handler()), {})
    assert await e.enrich("domain", "sbr-loans.cn") == {"supported": False}


async def test_rdap_bootstrap_failure_is_reported_not_raised(sbr_rules: ProjectRules) -> None:
    e = RdapEnricher(
        make_context(sbr_rules, connector_id="rdap", handler=lambda _r: httpx.Response(503)), {}
    )
    out = await e.enrich("domain", "sbr-loans.com")
    assert out["supported"] is None and out["error"].startswith("bootstrap")


async def test_rdap_non_json_response_is_reported_not_raised(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == BOOTSTRAP_URL:
            return httpx.Response(200, json=BOOTSTRAP)
        return httpx.Response(200, text="<html>maintenance</html>")

    e = RdapEnricher(make_context(sbr_rules, connector_id="rdap", handler=handler), {})
    assert await e.enrich("domain", "sbr-loans.com") == {
        "supported": True,
        "found": None,
        "error": "invalid_json",
    }
