from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from opti.connectors.otx.connector import OtxConnector, pulse_text
from opti.core.config import ProjectRules
from opti.sdk.base import MissingCredential
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

SECRETS = EnvSecretProvider({"OPTI_SECRET_OTX_API_KEY": "o" * 64})
PID = "6510f0c2a1b2c3d4e5f60718"


def _pulse(pid: str = PID, **change: Any) -> dict[str, Any]:
    return {"id": pid, "name": "Spear-phishing campaign against development banks",
            "description": "Lures impersonate the Sample Brand.", "author_name": "ExampleCERT",
            "modified": "2026-10-02T08:00:00.123000", "created": "2026-10-01T08:00:00", "tlp": "white",
            "tags": ["phishing", "banking"], "references": ["https://cert.example/report"], "adversary": "",
            "industries": ["Finance"], "targeted_countries": ["China", "Brazil"],
            "malware_families": [{"id": "Agent Tesla", "display_name": "Agent Tesla"}], **change}  # fmt: skip


def _conn(rules: ProjectRules, pulses: list[dict[str, Any]], seen: list[dict[str, list[str]]],
          cursors: MemoryCursorStore | None = None, **config: Any) -> OtxConnector:  # fmt: skip
    def handler(request: httpx.Request) -> httpx.Response:
        assert (
            request.headers["x-otx-api-key"] == "o" * 64
            and request.url.path == "/api/v1/search/pulses"
        )
        seen.append(parse_qs(urlsplit(str(request.url)).query))
        return httpx.Response(200, json={"count": len(pulses), "results": pulses, "next": None})

    ctx = make_context(rules, connector_id="otx", handler=handler, secrets=SECRETS, cursors=cursors)
    return OtxConnector(ctx, config)


async def test_otx_search(sbr_rules: ProjectRules) -> None:
    seen: list[dict[str, list[str]]] = []
    items = [
        i
        async for i in _conn(sbr_rules, [_pulse()], seen, max_queries=2).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert (
        len(seen) == 2
        and seen[0]["q"] == ['"Sample Brand"']
        and seen[0]["sort"] == ["-modified"]
    )
    doc = items[0].payload["document"]
    assert doc["url"] == f"https://otx.alienvault.com/pulse/{PID}" and doc["kind"] == "intel"
    assert (
        doc["source_name"] == "AlienVault OTX · ExampleCERT"
        and doc["published_at"] == "2026-10-02T08:00:00.123000+00:00"
    )
    assert (
        "Malware: Agent Tesla" in doc["text"]
        and "References: https://cert.example/report" in doc["text"]
    )
    assert items[0].source_item_id.startswith(f"{PID}#")


def test_pulse_text() -> None:
    text = pulse_text(
        _pulse(adversary="Example Panda", malware_families=["Remcos", {"name": "AsyncRAT"}, 5])
    )
    assert text.splitlines()[0] == "Lures impersonate the Sample Brand."
    assert "Adversary: Example Panda" in text and "Malware: Remcos, AsyncRAT" in text
    assert "Targeted countries: China, Brazil" in text


async def test_otx_filters_tlp_and_bad_ids(sbr_rules: ProjectRules) -> None:
    pulses = [
        _pulse("a" * 24, tlp="amber"), _pulse("b" * 24, tlp="red"), _pulse("../../etc"),
        _pulse("c" * 24, tlp=None, TLP="GREEN"), _pulse("d" * 24, tlp=None),
    ]  # fmt: skip
    items = [
        i
        async for i in _conn(sbr_rules, pulses, [], max_queries=1).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert [i.source_item_id.split("#")[0] for i in items] == ["c" * 24, "d" * 24]


async def test_otx_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    plan = build_query_plan(sbr_rules)
    assert (
        len([i async for i in _conn(sbr_rules, [_pulse()], [], cursors, max_queries=1).fetch(plan)])
        == 1
    )
    later = [_pulse("e" * 24, modified="2026-10-02T12:00:00"), _pulse("f" * 24, modified="2026-10-02T07:30:00"),
             _pulse("9" * 24, modified="2026-09-20T00:00:00")]  # fmt: skip
    items = [i async for i in _conn(sbr_rules, later, [], cursors, max_queries=1).fetch(plan)]
    assert [i.source_item_id.split("#")[0] for i in items] == [
        "e" * 24,
        "f" * 24,
    ]  # 1 小时重叠内的仍产出


async def test_otx_errors(sbr_rules: ProjectRules) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(403, json={"detail": "Authentication required"})

    conn = OtxConnector(
        make_context(sbr_rules, connector_id="otx", handler=handler, secrets=SECRETS), {}
    )
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
    assert len(calls) == 1  # 第一个查询失败即停止本轮（403 不重试）
    with pytest.raises(MissingCredential):
        OtxConnector(make_context(sbr_rules, connector_id="otx"), {}).validate_config()
