from typing import Any

import httpx

from opti.connectors.ransomlook.connector import RansomLookConnector
from opti.connectors.ransomware_live.connector import RansomwareLiveConnector
from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

LIVE = "https://api.ransomware.live/v2/recentvictims"


async def _run(conn_cls: Any, rules: ProjectRules, handler: Any, cursors: MemoryCursorStore,
               secrets: EnvSecretProvider | None = None, connector_id: str = "ransomware_live") -> list[Any]:  # fmt: skip
    ctx = make_context(
        rules, connector_id=connector_id, handler=handler, cursors=cursors, secrets=secrets
    )
    return [i async for i in conn_cls(ctx, {}).fetch(build_query_plan(rules))]


def _fixed(status: int, body: Any, seen: dict[str, Any] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == LIVE
        if seen is not None:
            seen["headers"] = dict(request.headers)
        return httpx.Response(status, json=body)

    return handler


VICTIMS = [
    {"victim": "Acme Inc", "group": "akira", "discovered": "2026-10-02 08:00:00.000000", "domain": "acme.example",
     "url": "https://www.ransomware.live/id/YWNtZQ"},
    {"post_title": "Beta Corp", "group_name": "play", "discovered": "2026-10-01T12:00:00Z"},  # 旧版字段名
    {"victim": "", "group": "play", "discovered": "2026-10-01"},  # 缺受害者：跳过
    "garbage",
]  # fmt: skip


async def test_field_aliases_and_overlap(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    items = await _run(RansomwareLiveConnector, sbr_rules, _fixed(200, VICTIMS), cursors)
    assert [i.source_item_id for i in items] == ["akira:acme", "play:beta"]
    assert items[0].payload["leak_post"]["links"] == ["https://www.ransomware.live/id/YWNtZQ"]
    assert cursors.get("ransomware_live", "since") == "2026-10-02T08:00:00+00:00"
    later = [
        {"victim": "Gamma LLC", "group": "akira", "discovered": "2026-10-03 01:00:00"},
        {
            "victim": "Delta SA",
            "group": "akira",
            "discovered": "2026-10-01 09:00:00",
        },  # 在 1 天重叠窗口内
        {
            "victim": "Old Co",
            "group": "akira",
            "discovered": "2026-09-20 00:00:00",
        },  # 早于游标：跳过
    ]
    items = await _run(RansomwareLiveConnector, sbr_rules, _fixed(200, later), cursors)
    assert [i.source_item_id for i in items] == ["akira:gamma", "akira:delta"]
    assert cursors.get("ransomware_live", "since") == "2026-10-03T01:00:00+00:00"


async def test_errors_do_not_advance_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    cursors.set("ransomware_live", "since", "2026-10-02T00:00:00+00:00")
    for status, body in [
        (429, {"error": "rate limited"}),
        (200, {"message": "maintenance"}),
        (200, "not json list"),
    ]:
        assert await _run(RansomwareLiveConnector, sbr_rules, _fixed(status, body), cursors) == []
        assert cursors.get("ransomware_live", "since") == "2026-10-02T00:00:00+00:00"
    wrapped = await _run(
        RansomwareLiveConnector,
        sbr_rules,
        _fixed(200, {"victims": VICTIMS[:1]}),
        MemoryCursorStore(),
    )
    assert [i.source_item_id for i in wrapped] == ["akira:acme"]


async def test_api_key_header(sbr_rules: ProjectRules) -> None:
    seen: dict[str, Any] = {}
    await _run(RansomwareLiveConnector, sbr_rules, _fixed(200, [], seen), MemoryCursorStore())
    assert "x-api-key" not in seen["headers"]
    secrets = EnvSecretProvider({"OPTI_SECRET_RANSOMWARE_LIVE_API_KEY": "pro-key"})
    await _run(
        RansomwareLiveConnector, sbr_rules, _fixed(200, [], seen), MemoryCursorStore(), secrets
    )
    assert seen["headers"]["x-api-key"] == "pro-key"


async def test_ransomlook_recent_and_self_hosted(sbr_rules: ProjectRules) -> None:
    posts = [
        {"post_title": "Acme Inc", "group_name": "akira", "discovered": "2026-10-02 08:00:00.123456",
         "description": "Acme is a provider of …", "link": "/group/akira"},
    ]  # fmt: skip
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=posts)

    ctx = make_context(
        sbr_rules, connector_id="ransomlook", handler=handler, cursors=MemoryCursorStore()
    )
    [item] = [i async for i in RansomLookConnector(ctx, {}).fetch(build_query_plan(sbr_rules))]
    assert seen == ["https://www.ransomlook.io/api/recent"]
    lp = item.payload["leak_post"]
    assert lp["key"] == "akira:acme" and lp["source"] == "ransomlook" and lp["links"] == []
    assert lp["other_links"] == ["/group/akira"]  # 相对地址不可点击
    ctx = make_context(
        sbr_rules, connector_id="ransomlook", handler=handler, cursors=MemoryCursorStore()
    )
    conn = RansomLookConnector(ctx, {"api_base": "https://ransomlook.internal.example/api"})
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert seen[-1] == "https://ransomlook.internal.example/api/recent"
