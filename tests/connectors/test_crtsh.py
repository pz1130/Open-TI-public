from typing import Any

import httpx

from opti.connectors.crtsh.connector import CrtshConnector
from opti.core.config import ProjectRules
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context


def _entry(id_: int, cn: str, names: str) -> dict[str, Any]:
    return {
        "issuer_ca_id": 295810,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "common_name": cn,
        "name_value": names,
        "id": id_,
        "entry_timestamp": "2026-09-30T10:00:00.123",
        "not_before": "2026-09-30T09:00:00",
        "not_after": "2026-12-29T09:00:00",
        "serial_number": "04ab",
        "result_count": 2,
    }


FIXTURE = [
    _entry(1001, "sbr-loans.com", "sbr-loans.com\nwww.sbr-loans.com\n*.sbr-loans.com"),
    _entry(1002, "sbrox.io", "sbrox.io"),
    _entry(1000, "sbr.int", "sbr.int\nmail.sbr.int"),
]


def _make(rules: ProjectRules, cursors: MemoryCursorStore, seen: list[str]) -> CrtshConnector:
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params["q"]
        seen.append(q)
        assert request.url.params["output"] == "json"
        if q == "sbr%":
            return httpx.Response(200, json=FIXTURE)
        if q == "%orbitbank%":
            return httpx.Response(502, text="<html>502 Bad Gateway</html>")
        if q == "%samplebrand%":
            return httpx.Response(200, text="<html>not json</html>")
        return httpx.Response(200, json=[])

    return CrtshConnector(
        make_context(rules, connector_id="crtsh", handler=handler, cursors=cursors), {}
    )


def test_compile_queries(sbr_rules: ProjectRules) -> None:
    conn = _make(sbr_rules, MemoryCursorStore(), [])
    queries = conn.compile_queries(build_query_plan(sbr_rules))
    assert queries[:6] == [
        "sbr%", "%.sbr%", "%-sbr%", "%sbr.%", "%samplebrand%", "%orbitbank%",
    ]  # fmt: skip
    affixes = sbr_rules.domains.restricted_tokens["orbit"]
    assert queries[6:] == [q for a in affixes for q in (f"%orbit%{a}%", f"%{a}%orbit%")]


def test_restricted_queries_strip_hyphens_and_dedupe(sbr_rules: ProjectRules) -> None:
    domains = sbr_rules.domains.model_copy(
        update={"restricted_tokens": {"e-x": ("pay", "pay", "lo-an")}}
    )
    rules = sbr_rules.model_copy(update={"domains": domains})
    conn = _make(rules, MemoryCursorStore(), [])
    queries = conn.compile_queries(build_query_plan(rules))
    assert queries[6:] == ["%ex%pay%", "%pay%ex%", "%ex%loan%", "%loan%ex%"]


def test_no_restricted_tokens_keeps_brand_queries_only(sbr_rules: ProjectRules) -> None:
    domains = sbr_rules.domains.model_copy(update={"restricted_tokens": {}})
    rules = sbr_rules.model_copy(update={"domains": domains})
    conn = _make(rules, MemoryCursorStore(), [])
    assert len(conn.compile_queries(build_query_plan(rules))) == 6


async def test_emits_matches_and_advances_cursor(sbr_rules: ProjectRules) -> None:
    cursors, seen = MemoryCursorStore(), []
    plan = build_query_plan(sbr_rules)
    items = [i async for i in _make(sbr_rules, cursors, seen).fetch(plan)]
    assert [i.source_item_id for i in items] == ["1001"]
    assert {m["domain"] for m in items[0].payload["matches"]} == {
        "sbr-loans.com",
        "www.sbr-loans.com",
    }
    assert items[0].url == "https://crt.sh/?id=1001"
    assert cursors.get("crtsh", "max_id:sbr%") == "1002"
    assert len(set(seen)) == 6 + 2 * len(sbr_rules.domains.restricted_tokens["orbit"])

    again = [i async for i in _make(sbr_rules, cursors, []).fetch(plan)]
    assert again == []


async def test_failed_query_is_skipped_and_cursor_untouched(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    items = [i async for i in _make(sbr_rules, cursors, []).fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1  # 502 与非 JSON 响应没有中断其他查询
    assert cursors.get("crtsh", "max_id:%orbitbank%") is None
    assert cursors.get("crtsh", "max_id:%samplebrand%") is None


def test_legacy_empty_effective_tokens_never_create_wildcard_queries(
    sbr_rules: ProjectRules,
) -> None:
    domains = sbr_rules.domains.model_copy(
        update={"brand_tokens": ("--",), "restricted_tokens": {"---": ("pay",), "silk": ("--",)}}
    )
    rules = sbr_rules.model_copy(update={"domains": domains})
    assert _make(rules, MemoryCursorStore(), []).compile_queries(build_query_plan(rules)) == []
