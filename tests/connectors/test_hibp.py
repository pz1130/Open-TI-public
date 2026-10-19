from typing import Any

import httpx
import pytest

from opti.connectors.hibp.connector import HibpConnector
from opti.core.config import ProjectRules
from opti.core.exposure import monitored_domains
from opti.sdk.base import MissingCredential
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

API = "https://haveibeenpwned.com/api/v3"
SECRETS = EnvSecretProvider({"OPTI_SECRET_HIBP_API_KEY": "k" * 32})
CATALOG = [
    {"Name": "NewLeak", "Title": "New Leak 2026", "BreachDate": "2026-08-01", "DataClasses": ["Passwords"], "IsVerified": True},
]  # fmt: skip


def _handler(state: dict[str, Any]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        state.setdefault("calls", []).append(url)
        if url == f"{API}/breaches":
            assert "hibp-api-key" not in request.headers  # 公开目录不发送密钥
            return httpx.Response(200, json=CATALOG)
        assert request.headers.get("hibp-api-key") == "k" * 32
        if url == f"{API}/subscribeddomains":
            return httpx.Response(200, json=[{"DomainName": "sbr.int", "PwnCount": 3}])
        if url == f"{API}/breacheddomain/sbr.int":
            return httpx.Response(200, json=state["domain"])
        return httpx.Response(404)

    return handler


async def _run(
    rules: ProjectRules, state: dict[str, Any], cursors: MemoryCursorStore, **config: Any
) -> list[Any]:
    ctx = make_context(
        rules, connector_id="hibp", handler=_handler(state), secrets=SECRETS, cursors=cursors
    )
    conn = HibpConnector(ctx, config)
    return [i async for i in conn.fetch(build_query_plan(rules))]


def test_monitored_domains() -> None:
    assert monitored_domains(("example.org",), []) == ["example.org"]
    assert monitored_domains(("example.org",), ["Mail.Example.org", "evil.org", "example.org", "mail.example.org"]) == [
        "mail.example.org", "example.org",
    ]  # fmt: skip


async def test_breaches_grouped_with_accounts(sbr_rules: ProjectRules) -> None:
    state = {"domain": {"alice": ["NewLeak", "Mystery"], "bob": ["NewLeak"]}}
    items = await _run(sbr_rules, state, MemoryCursorStore())
    by_key = {i.payload["exposure"]["key"]: i.payload["exposure"] for i in items}
    assert set(by_key) == {"hibp:sbr.int:NewLeak", "hibp:sbr.int:Mystery"}
    leak = by_key["hibp:sbr.int:NewLeak"]
    assert leak["accounts"] == ["alice@sbr.int", "bob@sbr.int"] and leak["affected"] == 2
    assert leak["data_classes"] == ["Passwords"] and leak["title"] == "New Leak 2026"


async def test_unknown_breach_is_low_confidence(sbr_rules: ProjectRules) -> None:
    items = await _run(sbr_rules, {"domain": {"alice": ["Mystery"]}}, MemoryCursorStore())
    [ex] = [i.payload["exposure"] for i in items]
    assert ex["title"] == "Mystery" and ex["verified"] is False and ex["data_classes"] == []


async def test_unchanged_breach_is_not_repeated(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    state = {"domain": {"alice": ["NewLeak"]}}
    assert len(await _run(sbr_rules, state, cursors)) == 1
    assert await _run(sbr_rules, state, cursors) == []  # 名单没变：不再产生数据
    state["domain"] = {"alice": ["NewLeak"], "carol": ["NewLeak"]}
    [item] = await _run(sbr_rules, state, cursors)
    assert item.payload["exposure"]["accounts"] == ["alice@sbr.int", "carol@sbr.int"]


async def test_large_breach_is_split_without_losing_accounts(sbr_rules: ProjectRules) -> None:
    state = {"domain": {f"user{i}": ["NewLeak"] for i in range(5001)}}
    items = await _run(sbr_rules, state, MemoryCursorStore())
    assert len(items) == 2
    assert all(i.payload["exposure"]["affected"] == 5001 for i in items)
    assert len({email for i in items for email in i.payload["exposure"]["accounts"]}) == 5001


async def test_unverified_domains_and_errors(sbr_rules: ProjectRules) -> None:
    state = {"domain": {"alice": ["NewLeak"]}}
    # 只查询在 HIBP 后台验证过的域名
    items = await _run(sbr_rules, state, MemoryCursorStore(), domains=["mail.sbr.int"])
    assert items == [] and not any("breacheddomain" in c for c in state["calls"])
    ctx = make_context(
        sbr_rules, connector_id="hibp", handler=lambda _r: httpx.Response(503), secrets=SECRETS
    )
    assert [i async for i in HibpConnector(ctx, {}).fetch(build_query_plan(sbr_rules))] == []
    with pytest.raises(MissingCredential):
        HibpConnector(make_context(sbr_rules, connector_id="hibp"), {}).validate_config()
