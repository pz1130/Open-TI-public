from typing import Any

import httpx
import pytest

from opti.connectors.threatfox.connector import ThreatFoxConnector, threatfox_records
from opti.core.config import ProjectRules
from opti.sdk.base import MissingCredential
from opti.sdk.context import EnvSecretProvider
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

SECRETS = EnvSecretProvider({"OPTI_SECRET_THREATFOX_AUTH_KEY": "t" * 48})
EXPORT = {
    "1600001": [{"ioc_value": "sbr-secure-login.top", "ioc_type": "domain", "threat_type": "botnet_cc",
                 "malware_printable": "Agent Tesla", "confidence_level": 75,
                 "first_seen_utc": "2026-10-02 08:00:00", "tags": "AgentTesla,phishing"}],
    "1600002": [{"ioc_value": "https://evil.example/sbr/login.php", "ioc_type": "url",
                 "threat_type": "payload_delivery", "confidence_level": 25, "tags": None}],
    "1600003": [{"ioc_value": "203.0.113.7:443", "ioc_type": "ip:port", "confidence_level": 100}],
    "1600004": [{"ioc_value": "weather.example", "ioc_type": "domain", "confidence_level": 100}],
    "1600005": [{"ioc_value": "0" * 32, "ioc_type": "md5_hash", "confidence_level": 100}],
}  # fmt: skip


async def _items(rules: ProjectRules, doc: Any, **config: Any) -> list[Any]:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET" and request.headers["auth-key"] == "t" * 48
        return httpx.Response(200, json=doc)

    conn = ThreatFoxConnector(
        make_context(rules, connector_id="threatfox", handler=handler, secrets=SECRETS), config
    )
    return [i async for i in conn.fetch(build_query_plan(rules))]


async def test_export_shapes_and_types(sbr_rules: ProjectRules) -> None:
    items = await _items(sbr_rules, EXPORT)
    assert [(i.payload["feed_url"], i.payload["kind"]) for i in items] == [
        ("http://sbr-secure-login.top/", "domain"), ("https://evil.example/sbr/login.php", "url"),
    ]  # fmt: skip
    first, second = (i.payload["intel"] for i in items)
    assert first == {"confirmed": True, "threat": "botnet_cc", "malware": "Agent Tesla", "confidence": 75,
                     "tags": ["AgentTesla", "phishing"], "first_seen": "2026-10-02 08:00:00",
                     "threatfox_id": "1600001", "source": "threatfox"}  # fmt: skip
    assert second["confirmed"] is False and second["tags"] == []  # 置信度 25 低于默认 50
    assert [
        i.payload["intel"]["confirmed"] for i in await _items(sbr_rules, EXPORT, min_confidence=20)
    ] == [True, True]
    api = {"query_status": "ok", "data": [{"id": 77, "ioc": "sbr-secure-login.top", "ioc_type": "domain",
                                           "confidence_level": "90", "tags": ["c2"]}]}  # fmt: skip
    [item] = await _items(sbr_rules, api)
    assert item.payload["intel"]["threatfox_id"] == "77" and item.payload["intel"]["tags"] == ["c2"]


def test_threatfox_records_ignores_garbage() -> None:
    assert list(threatfox_records([])) == []
    assert list(threatfox_records({"query_status": "unknown_auth_key"})) == []
    assert list(threatfox_records({"1": ["x", {"ioc_value": "a"}]})) == [("1", {"ioc_value": "a"})]


async def test_threatfox_errors(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"query_status": "unknown_auth_key"})

    conn = ThreatFoxConnector(
        make_context(sbr_rules, connector_id="threatfox", handler=handler, secrets=SECRETS), {}
    )
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
    assert await _items(sbr_rules, {"query_status": "unknown_auth_key"}) == []
    with pytest.raises(MissingCredential):
        ThreatFoxConnector(make_context(sbr_rules, connector_id="threatfox"), {}).validate_config()
