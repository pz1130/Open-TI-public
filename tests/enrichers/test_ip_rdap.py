import ipaddress
from typing import Any

import httpx

from opti.core.config import ProjectRules
from opti.enrichers.ip_rdap.enricher import (
    BOOTSTRAP_V4,
    IpRdapEnricher,
    lookup_base,
    parse_ip_bootstrap,
    parse_ip_rdap,
)
from opti.sdk.testing import make_context

BOOTSTRAP = {
    "services": [
        [["104.0.0.0/8", "45.0.0.0/8"], ["http://rdap.arin.example/registry/", "https://rdap.arin.example/registry/"]],
        [["104.16.0.0/12"], ["https://rdap.more-specific.example/"]],
        [["not-a-prefix"], ["https://broken.example/"]],
    ]
}  # fmt: skip

IP_DOC: dict[str, Any] = {
    "objectClassName": "ip network",
    "handle": "NET-104-16-0-0-1",
    "name": "CLOUDFLARENET",
    "country": "US",
    "startAddress": "104.16.0.0",
    "endAddress": "104.31.255.255",
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
            "entities": [
                {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@cloudflare.example"]]]}
            ],
        }
    ],
}  # fmt: skip


def test_bootstrap_longest_prefix_and_https() -> None:
    table = parse_ip_bootstrap(BOOTSTRAP)
    assert (
        lookup_base(table, ipaddress.ip_address("104.16.1.1"))
        == "https://rdap.more-specific.example/"
    )
    assert (
        lookup_base(table, ipaddress.ip_address("45.33.32.156"))
        == "https://rdap.arin.example/registry/"
    )
    assert lookup_base(table, ipaddress.ip_address("8.8.8.8")) is None


def test_parse_ip_rdap() -> None:
    out = parse_ip_rdap(IP_DOC)
    assert out == {
        "network_name": "CLOUDFLARENET", "handle": "NET-104-16-0-0-1", "country": "US",
        "start": "104.16.0.0", "end": "104.31.255.255", "org": "Cloudflare, Inc.",
        "abuse_email": "abuse@cloudflare.example",
    }  # fmt: skip
    assert parse_ip_rdap({"entities": "broken"})["org"] is None


def _handler(status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == BOOTSTRAP_V4:
            return httpx.Response(200, json=BOOTSTRAP)
        if url == "https://rdap.more-specific.example/ip/104.16.1.1":
            return httpx.Response(status, json=IP_DOC if status == 200 else {})
        return httpx.Response(500)

    return handler


async def test_enrich_found(sbr_rules: ProjectRules) -> None:
    e = IpRdapEnricher(make_context(sbr_rules, connector_id="ip_rdap", handler=_handler()), {})
    out = await e.enrich("ip", "104.16.1.1")
    assert out["found"] is True and out["network_name"] == "CLOUDFLARENET"


async def test_enrich_errors_are_reported_not_raised(sbr_rules: ProjectRules) -> None:
    e = IpRdapEnricher(make_context(sbr_rules, connector_id="ip_rdap", handler=_handler(429)), {})
    assert (await e.enrich("ip", "104.16.1.1"))["error"] == "429"
    e = IpRdapEnricher(make_context(sbr_rules, connector_id="ip_rdap", handler=_handler(404)), {})
    assert await e.enrich("ip", "104.16.1.1") == {"supported": True, "found": False}
    assert await e.enrich("ip", "10.0.0.1") == {"supported": False}  # 内网地址不查
    assert (await e.enrich("ip", "not-an-ip"))["error"] == "invalid_ip"
    broken = IpRdapEnricher(
        make_context(sbr_rules, connector_id="ip_rdap", handler=lambda _r: httpx.Response(503)), {}
    )
    assert (await broken.enrich("ip", "104.16.1.1"))["error"].startswith("bootstrap")
