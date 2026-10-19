import asyncio
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from opti.db.models import AuditLog, DashboardLayout

pytestmark = pytest.mark.db


def _layout(*types: str, days: int = 30) -> dict[str, Any]:
    return {
        "version": 1,
        "days": days,
        "widgets": [
            {"id": f"w{i}", "type": t, "x": 0, "y": i * 4, "w": 6, "h": 4, "params": {}}
            for i, t in enumerate(types)
        ],
    }


async def _actions(api: Any) -> list[str]:
    async with api.sessions() as s:
        return list((await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all())


async def test_personal_layout_falls_back_to_default_then_builtin(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("vic", ("viewer",))
    await make_user("ops", ("platform_admin",))
    vic, ops = await login("vic"), await login("ops")
    assert (await vic.get("/api/v1/dashboard/layout")).json() == {
        "layout": None, "source": "builtin",
    }  # fmt: skip

    r = await ops.put("/api/v1/dashboard/layout/default", json=_layout("trend", "connector_health"))
    assert r.status_code == 200, r.text
    got = (await vic.get("/api/v1/dashboard/layout")).json()
    assert got["source"] == "default" and len(got["layout"]["widgets"]) == 2

    r = await vic.put("/api/v1/dashboard/layout", json=_layout("top", days=7))
    assert r.status_code == 200 and r.json()["source"] == "user"
    got = (await vic.get("/api/v1/dashboard/layout")).json()
    assert got["source"] == "user" and got["layout"]["days"] == 7
    # 再次保存是覆盖，不是新增
    await vic.put("/api/v1/dashboard/layout", json=_layout("top", "mttd"))
    async with api.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(DashboardLayout)) == 2

    assert (await vic.delete("/api/v1/dashboard/layout")).status_code == 204
    assert (await vic.get("/api/v1/dashboard/layout")).json()["source"] == "default"
    assert (await vic.delete("/api/v1/dashboard/layout")).status_code == 204  # 不存在也成功


async def test_default_layout_requires_permission_and_is_audited(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()  # analyst
    await make_user("ops", ("platform_admin",))
    alice, ops = await login(), await login("ops")
    assert (await alice.get("/api/v1/dashboard/layout/default")).status_code == 403
    assert (
        await alice.put("/api/v1/dashboard/layout/default", json=_layout("trend"))
    ).status_code == 403
    assert (await alice.delete("/api/v1/dashboard/layout/default")).status_code == 403

    assert (await ops.get("/api/v1/dashboard/layout/default")).json() == {"layout": None}
    await ops.put("/api/v1/dashboard/layout/default", json=_layout("trend", "top", "trend"))
    await ops.put("/api/v1/dashboard/layout/default", json=_layout("mttd"))
    got = (await ops.get("/api/v1/dashboard/layout/default")).json()
    assert [w["type"] for w in got["layout"]["widgets"]] == ["mttd"]
    async with api.sessions() as s:
        rows = (await s.scalars(select(DashboardLayout))).all()
        assert len(rows) == 1 and rows[0].user_id is None  # 机构默认只有一行
        first = await s.scalar(
            select(AuditLog).where(AuditLog.action == "dashboard.default.update").limit(1)
        )
        assert first is not None and first.detail == {"widgets": 3, "types": ["top", "trend"]}

    assert (await ops.delete("/api/v1/dashboard/layout/default")).status_code == 204
    assert (await ops.get("/api/v1/dashboard/layout/default")).json() == {"layout": None}
    assert (await _actions(api))[-3:] == [
        "dashboard.default.update", "dashboard.default.update", "dashboard.default.clear",
    ]  # fmt: skip


async def test_invalid_layout_rejected_and_stale_rows_ignored(
    api: Any, make_user: Any, login: Any
) -> None:
    uid = await make_user("vic", ("viewer",))
    vic = await login("vic")
    bad = _layout("trend")
    bad["widgets"][0]["x"] = 10  # x + w = 16 > 12
    assert (await vic.put("/api/v1/dashboard/layout", json=bad)).status_code == 422
    # 库里残留了不再合法的布局（比如校验规则收紧后）：当作不存在
    async with api.sessions.begin() as s:
        s.add(DashboardLayout(user_id=uid, layout={"version": 99}, updated_at=api.clock()))
    assert (await vic.get("/api/v1/dashboard/layout")).json()["source"] == "builtin"


async def test_only_one_default_row(api: Any, make_user: Any) -> None:
    await make_user()
    with pytest.raises(IntegrityError):
        async with api.sessions.begin() as s:
            s.add(DashboardLayout(user_id=None, layout=_layout(), updated_at=api.clock()))
            s.add(DashboardLayout(user_id=None, layout=_layout(), updated_at=api.clock()))
            await s.flush()


async def test_layout_requires_login(api: Any) -> None:
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as anon:
        assert (await anon.get("/api/v1/dashboard/layout")).status_code == 401


async def test_concurrent_default_saves_keep_one_row(api: Any, make_user: Any, login: Any) -> None:
    await make_user("ops", ("platform_admin",))
    first, second = await login("ops"), await login("ops")
    responses = await asyncio.gather(
        first.put("/api/v1/dashboard/layout/default", json=_layout("trend")),
        second.put("/api/v1/dashboard/layout/default", json=_layout("mttd")),
    )
    assert [r.status_code for r in responses] == [200, 200]
    async with api.sessions() as s:
        rows = (await s.scalars(select(DashboardLayout))).all()
    assert len(rows) == 1 and rows[0].user_id is None
    assert rows[0].layout["widgets"][0]["type"] in {"trend", "mttd"}
