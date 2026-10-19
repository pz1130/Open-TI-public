from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.db
UserFactory = Callable[..., Awaitable[int]]


async def test_manual_rule_lifecycle(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user()
    c = await login()
    r = await c.post(
        "/api/v1/suppressions",
        json={
            "kind": "registered_domain",
            "value": "www.sbrbank.com",
            "reason": "SBR Bank PLC",
            "expires_days": 30,
        },
    )
    assert r.status_code == 201
    rule = r.json()
    assert rule["value"] == "sbrbank.com" and rule["active"] and rule["created_by"] == "alice"
    assert (
        await c.post("/api/v1/suppressions", json={"kind": "regex", "value": ".*", "reason": "x"})
    ).status_code == 422
    assert (
        await c.post("/api/v1/suppressions", json={"kind": "domain", "value": "???", "reason": "x"})
    ).status_code == 422
    assert [x["id"] for x in (await c.get("/api/v1/suppressions")).json()] == [rule["id"]]
    assert (await c.delete(f"/api/v1/suppressions/{rule['id']}")).status_code == 204
    assert (await c.delete(f"/api/v1/suppressions/{rule['id']}")).status_code == 404
    assert (await c.get("/api/v1/suppressions")).json() == []
    inactive = (await c.get("/api/v1/suppressions", params={"include_inactive": True})).json()
    assert inactive[0]["active"] is False and inactive[0]["revoked_at"] is not None


async def test_audit_log_access_and_verification(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    await make_user("audrey", roles=("auditor",))
    analyst = await login()
    auditor = await login("audrey")
    assert (await analyst.get("/api/v1/audit-logs")).status_code == 403
    assert (await auditor.get("/api/v1/alerts")).status_code == 403
    page = (await auditor.get("/api/v1/audit-logs")).json()
    assert [e["action"] for e in page["items"]] == ["auth.login", "auth.login"]  # 倒序
    assert page["items"][0]["actor"] == "audrey"
    only = (await auditor.get("/api/v1/audit-logs", params={"actor": "alice"})).json()
    assert [e["actor"] for e in only["items"]] == ["alice"]
    second = (await auditor.get("/api/v1/audit-logs", params={"page": 2, "limit": 1})).json()
    assert second["total"] == 2 and second["items"][0]["actor"] == "alice"
    filtered = (
        await auditor.get("/api/v1/audit-logs", params={"page": 2, "limit": 1, "actor": "alice"})
    ).json()
    assert filtered["total"] == 1 and filtered["items"] == []
    assert (await auditor.get("/api/v1/audit-logs/verify")).json()["ok"] is True
    async with api.sessions.begin() as s:
        await s.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
        await s.execute(text("UPDATE audit_log SET actor = 'mallory' WHERE actor = 'alice'"))
        await s.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    v = (await auditor.get("/api/v1/audit-logs/verify")).json()
    assert v["ok"] is False and v["first_broken_id"] == only["items"][0]["id"]
