from typing import Any

import httpx

from opti.connectors.hudsonrock.connector import API, HudsonRockConnector
from opti.core.config import ProjectRules
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context


async def _run(
    rules: ProjectRules, response: Any, cursors: MemoryCursorStore, status: int = 200
) -> list[Any]:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{API}?domain=sbr.int"
        return httpx.Response(status, json=response)

    ctx = make_context(rules, connector_id="hudsonrock", handler=handler, cursors=cursors)
    connector = HudsonRockConnector(ctx, {"api_url": API, "schema_verified": True})
    connector.validate_config()
    return [i async for i in connector.fetch(build_query_plan(rules))]


async def test_unverified_api_is_blocked(sbr_rules: ProjectRules) -> None:
    import pytest

    ctx = make_context(sbr_rules, connector_id="hudsonrock")
    with pytest.raises(ValueError, match="尚未核对"):
        HudsonRockConnector(ctx, {"schema_verified": False}).validate_config()


DOC = {"total": 120, "employees": 2, "users": 110, "third_parties": 8,
       "last_employee_compromised": "2026-09-20T11:00:00.000Z", "last_user_compromised": "2026-09-30T00:00:00.000Z"}  # fmt: skip


async def test_stealer_statistics(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    [item] = await _run(sbr_rules, DOC, cursors)
    ex = item.payload["exposure"]
    assert ex["kind"] == "stealer" and ex["key"] == "hudsonrock:sbr.int" and ex["affected"] == 2
    assert ex["breach_date"] == "2026-09-20" and ex["accounts"] == []
    assert ex["context"] == {"users": 110, "third_parties": 8, "total": 120}
    assert await _run(sbr_rules, DOC, cursors) == []  # 没有变化不再产生数据
    [changed] = await _run(sbr_rules, {**DOC, "employees": 3}, cursors)
    assert changed.payload["exposure"]["affected"] == 3


async def test_no_employees_or_errors_produce_nothing(sbr_rules: ProjectRules) -> None:
    assert await _run(sbr_rules, {**DOC, "employees": 0}, MemoryCursorStore()) == []
    assert await _run(sbr_rules, {"message": "rate limited"}, MemoryCursorStore(), status=429) == []
    assert await _run(sbr_rules, ["unexpected"], MemoryCursorStore()) == []
