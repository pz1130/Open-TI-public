from typing import Any

import pytest
from sqlalchemy import select

from opti.configs import revisions
from opti.configs.runtime import ConfigRuntime
from opti.db.models import AuditLog

pytestmark = pytest.mark.db
CONFIG = "/api/v1/connectors/otx/config"
APPROVAL = "/api/v1/connectors/otx/approval"


async def _clients(api: Any, make_user: Any, login: Any) -> tuple[Any, Any, Any]:
    api.deps.config = ConfigRuntime.static(api.rules, sessions=api.sessions)
    await make_user("ops", ("platform_admin",))
    await make_user("legal", ("compliance_officer",))
    await make_user("alice", ("analyst",))  # 只读：connectors:read
    return await login("ops"), await login("legal"), await login("alice")


def _cfg(enabled: bool, max_queries: int = 10) -> dict[str, Any]:
    return {"enabled": enabled, "plan": "free", "config": {"max_queries": max_queries}}


async def test_history_lists_only_versions_that_changed_this_connector(
    api: Any, make_user: Any, login: Any
) -> None:
    ops, legal, reader = await _clients(api, make_user, login)
    await ops.put(CONFIG, json=_cfg(True, 5))  # v1
    await ops.put(
        "/api/v1/connectors/urlscan/config", json={"enabled": True, "plan": "free", "config": {}}
    )  # v2
    await legal.put(APPROVAL, json={"license_approved": True, "license_ref": "LEGAL-9"})  # v3
    r = await reader.get("/api/v1/connectors/otx/history")
    assert r.status_code == 200, r.text
    rows = r.json()
    assert [x["version"] for x in rows] == [3, 1]
    assert rows[0]["changed"] == ["license_approved", "license_ref"]
    assert rows[0]["created_by"] == "legal" and rows[0]["restorable"] is False
    assert rows[1]["changed"] == ["config"]
    assert "+  max_queries: 5" in rows[1]["diff"] and rows[1]["diff"].startswith("--- v0")
    assert rows[1]["restorable"] is False  # 与当前参数相同


async def test_restore_brings_back_parameters_only(api: Any, make_user: Any, login: Any) -> None:
    ops, legal, reader = await _clients(api, make_user, login)
    await ops.put(CONFIG, json=_cfg(True, 5))  # v1
    await legal.put(APPROVAL, json={"license_approved": True, "license_ref": "LEGAL-9"})  # v2
    await ops.put(CONFIG, json=_cfg(False, 7))  # v3
    assert (
        await reader.post("/api/v1/connectors/otx/restore", json={"version": 1})
    ).status_code == 403
    assert (
        await legal.post("/api/v1/connectors/otx/restore", json={"version": 1})
    ).status_code == 403
    r = await ops.post("/api/v1/connectors/otx/restore", json={"version": 1})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 4 and body["enabled"] is True and body["config"]["max_queries"] == 5
    assert body["license_approved"] is True and body["license_ref"] == "LEGAL-9"  # 批准不动
    again = await ops.post("/api/v1/connectors/otx/restore", json={"version": 1})
    assert again.status_code == 409 and again.json()["detail"]["reason"] == "nothing_to_restore"
    history = (await ops.get("/api/v1/connectors/otx/history")).json()
    assert history[0]["version"] == 4 and history[0]["note"] == "恢复 v1 的参数"
    assert history[0]["restored_from"] == 1
    async with api.sessions() as s:
        detail = await s.scalar(
            select(AuditLog.detail).where(AuditLog.action == "connector.restored")
        )
    assert detail == {"version": 4, "restored_from": 1, "changed": ["enabled", "config"]}


async def test_restore_to_a_version_without_this_connector_returns_to_yaml(
    api: Any, make_user: Any, login: Any
) -> None:
    ops, _, _ = await _clients(api, make_user, login)
    await ops.put(
        "/api/v1/connectors/urlscan/config", json={"enabled": True, "plan": "free", "config": {}}
    )  # v1
    await ops.put(CONFIG, json=_cfg(False, 3))  # v2
    r = await ops.post("/api/v1/connectors/otx/restore", json={"version": 1})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True  # otx.yaml 中 enabled: true
    assert r.json()["config"] == {}  # YAML 原值，不是 manifest 默认值


async def test_unknown_version_and_connector(api: Any, make_user: Any, login: Any) -> None:
    ops, _, _ = await _clients(api, make_user, login)
    assert (
        await ops.post("/api/v1/connectors/otx/restore", json={"version": 9})
    ).status_code == 404
    assert (await ops.get("/api/v1/connectors/nope/history")).status_code == 404


async def test_generic_config_routes_cannot_write_connectors(
    api: Any, make_user: Any, login: Any
) -> None:
    ops, _, reader = await _clients(api, make_user, login)
    await ops.put(CONFIG, json=_cfg(True, 5))
    assert (await reader.get("/api/v1/config/connectors")).json()["version"] == 1
    put = await ops.put(
        "/api/v1/config/connectors", json={"data": {"connectors": {}}, "base_version": 1}
    )
    assert put.status_code == 403 and put.json()["detail"]["reason"] == "use_connector_endpoints"
    restore = await ops.post(
        "/api/v1/config/connectors/revisions/1/restore", json={"base_version": 1}
    )
    assert restore.status_code == 403
    assert (await ops.get("/api/v1/config/connectors/secrets")).status_code == 403


async def test_never_changed_connector_has_empty_history(
    api: Any, make_user: Any, login: Any
) -> None:
    ops, _, _ = await _clients(api, make_user, login)
    await ops.put(CONFIG, json=_cfg(True, 5))
    assert (await ops.get("/api/v1/connectors/crtsh/history")).json() == []


async def test_restoring_parameters_that_no_longer_validate_is_rejected(
    api: Any, make_user: Any, login: Any
) -> None:
    ops, _, _ = await _clients(api, make_user, login)
    stale = "connectors:\n  otx:\n    enabled: true\n    config:\n      max_queries: 999\n"
    async with api.sessions.begin() as s:  # 旧版本按当时的 manifest 合法，现在上限已是 20
        await revisions.append(
            s, "connectors", stale, base_version=0, user="t", note=None, now=api.clock()
        )
    await ops.put(CONFIG, json=_cfg(True, 5))  # v2
    r = await ops.post("/api/v1/connectors/otx/restore", json={"version": 1})
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["path"] == "connectors.otx.config"
    assert (await ops.get(CONFIG)).json()["version"] == 2
    # 无法解析的旧版本不让历史出错，只是不参与比较
    history = await ops.get("/api/v1/connectors/otx/history")
    assert history.status_code == 200
    assert [x["version"] for x in history.json()] == [2]


async def test_another_connectors_stale_parameters_do_not_hide_or_block_this_one(
    api: Any, make_user: Any, login: Any
) -> None:
    ops, _, _ = await _clients(api, make_user, login)
    stale = (
        "connectors:\n  otx:\n    enabled: true\n    config:\n      max_queries: 999\n"
        "  urlscan:\n    enabled: false\n    plan: free\n"
    )
    async with api.sessions.begin() as s:  # v1：otx 的参数按当时的 manifest 合法，现在已超上限
        await revisions.append(
            s, "connectors", stale, base_version=0, user="t", note=None, now=api.clock()
        )
    urlscan = "/api/v1/connectors/urlscan"
    await ops.put(f"{urlscan}/config", json={"enabled": True, "plan": "free", "config": {}})  # v2
    history = (await ops.get(f"{urlscan}/history")).json()
    assert [x["version"] for x in history] == [2, 1]
    r = await ops.post(f"{urlscan}/restore", json={"version": 1})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
