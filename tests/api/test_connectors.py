import asyncio
from typing import Any

import pytest
from sqlalchemy import select

from opti.configs import kinds, revisions
from opti.configs import secrets as config_secrets
from opti.configs.runtime import ConfigRuntime
from opti.core.secretbox import Keyring, generate_key
from opti.db.models import AuditLog, ConfigSecret

pytestmark = pytest.mark.db


async def test_connectors_api(
    api: Any, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPTI_SECRET_URLSCAN_API_KEY", "leaky-secret-value-123")
    await make_user("ops", ("platform_admin",))
    await make_user("alice", ("analyst",))
    await make_user("vic", ("viewer",))
    r = await (await login("ops")).get("/api/v1/connectors")
    assert r.status_code == 200, r.text
    rows = {c["id"]: c for c in r.json()}
    u = rows["urlscan"]
    assert (
        u["tier"] == "freemium" and u["category"] == "phishing" and u["license_approved"] is False
    )
    assert u["health"] == "blocked" and u["reason"].startswith("license_not_approved")
    assert u["credentials"] == [
        {"name": "api_key", "required": False, "configured": True, "problem": None}
    ]
    assert "leaky-secret-value-123" not in r.text  # 只给出是否已设置
    assert rows["crtsh"]["tier"] == "free" and rows["crtsh"]["location"] == "platform"
    assert (await (await login("alice")).get("/api/v1/connectors")).status_code == 200
    assert (await (await login("vic")).get("/api/v1/connectors")).status_code == 403


def _keyed(api: Any) -> Keyring:
    keyring = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    assert keyring is not None
    api.deps.keyring = keyring
    api.deps.config = ConfigRuntime.static(api.rules, sessions=api.sessions, keyring=keyring)
    return keyring


async def _head(api: Any) -> dict[str, Any]:
    async with api.sessions() as s:
        row = await revisions.latest(s, "connectors")
    assert row is not None
    return kinds.to_data("connectors", kinds.parse("connectors", row.content))["connectors"]


async def test_connector_web_config_and_approval_are_separate(
    api: Any, make_user: Any, login: Any
) -> None:
    _keyed(api)
    await make_user("ops", ("platform_admin",))
    await make_user("legal", ("compliance_officer",))
    await make_user("alice", ("analyst",))
    ops, legal, analyst = await login("ops"), await login("legal"), await login("alice")
    config_url = "/api/v1/connectors/otx/config"
    approval_url = "/api/v1/connectors/otx/approval"
    assert (
        await analyst.put(config_url, json={"enabled": True, "plan": "free", "config": {}})
    ).status_code == 403
    assert (
        await ops.put(approval_url, json={"license_approved": True, "license_ref": "LEGAL-1"})
    ).status_code == 403
    r = await ops.put(
        config_url,
        json={
            "enabled": True,
            "plan": "free",
            "config": {},
            "secrets": {"api_key": "web-secret-value"},
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 1
    assert r.json()["credentials"][0]["configured"] is True
    assert "web-secret-value" not in r.text
    async with api.sessions() as s:
        stored = await s.get(ConfigSecret, ("connectors", "otx:api_key"))
    assert stored is not None and stored.value_enc and b"web-secret-value" not in stored.value_enc
    assert (await legal.put(approval_url, json={"license_approved": True})).status_code == 422
    r = await legal.put(approval_url, json={"license_approved": True, "license_ref": "LEGAL-1"})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 2
    head = await _head(api)
    assert head["otx"]["enabled"] is True and head["otx"]["license_ref"] == "LEGAL-1"
    rows = {x["id"]: x for x in (await ops.get("/api/v1/connectors")).json()}
    assert rows["otx"]["runnable"] is True
    assert rows["otx"]["license_ref"] == "LEGAL-1"
    async with api.sessions() as s:
        audits = (
            await s.execute(
                select(AuditLog.action, AuditLog.detail)
                .where(AuditLog.target_type == "connector")
                .order_by(AuditLog.id)
            )
        ).all()
    assert [a for a, _ in audits] == ["connector.config_updated", "connector.approval_updated"]
    # YAML 里 otx 已启用；这次变化的是参数补上了 manifest 默认值
    assert audits[0][1]["version"] == 1 and audits[0][1]["changed"] == ["config"]
    assert audits[0][1]["credentials_changed"] == ["api_key"]
    assert audits[1][1]["changed"] == ["license_approved", "license_ref"]


async def test_unchanged_save_keeps_version(api: Any, make_user: Any, login: Any) -> None:
    _keyed(api)
    await make_user("ops", ("platform_admin",))
    ops = await login("ops")
    body = {"enabled": True, "plan": "free", "config": {}}
    assert (await ops.put("/api/v1/connectors/otx/config", json=body)).json()["version"] == 1
    again = await ops.put("/api/v1/connectors/otx/config", json=body)
    assert again.status_code == 200 and again.json()["version"] == 1
    secret_only = await ops.put(
        "/api/v1/connectors/otx/config", json={**body, "secrets": {"api_key": "k" * 16}}
    )
    assert secret_only.json()["version"] == 1  # 只改凭据不生成版本
    assert secret_only.json()["credentials"][0]["configured"] is True


async def test_saves_to_different_connectors_are_both_kept(
    api: Any, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _keyed(api)
    await make_user("ops", ("platform_admin",))
    ops = await login("ops")
    # Both commits finish before either response is assembled: each response must
    # retain its own saved version rather than reporting the latest shared snapshot.
    barrier = asyncio.Barrier(2)
    refresh = api.deps.config.refresh

    async def synchronized_refresh():
        await barrier.wait()
        await refresh()

    monkeypatch.setattr(api.deps.config, "refresh", synchronized_refresh)
    first, second = await asyncio.gather(
        ops.put(
            "/api/v1/connectors/otx/config", json={"enabled": True, "plan": "free", "config": {}}
        ),
        ops.put(
            "/api/v1/connectors/urlscan/config",
            json={"enabled": True, "plan": "free", "config": {}},
        ),
    )
    assert first.status_code == second.status_code == 200
    head = await _head(api)
    assert head["otx"]["enabled"] is True and head["urlscan"]["enabled"] is True
    assert sorted([first.json()["version"], second.json()["version"]]) == [1, 2]


async def test_undecryptable_credential_is_shown(api: Any, make_user: Any, login: Any) -> None:
    _keyed(api)
    other = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    async with api.sessions.begin() as s:
        await config_secrets.write(
            s, "connectors", {"otx:api_key": "x" * 20}, keyring=other, user="t", now=api.clock()
        )
    await api.deps.config.refresh()
    await make_user("ops", ("platform_admin",))
    r = await (await login("ops")).get("/api/v1/connectors/otx/config")
    [cred] = r.json()["credentials"]
    assert cred["configured"] is False and "无法解密" in cred["problem"]
    catalog = await (await login("ops")).get("/api/v1/connectors")
    row = next(item for item in catalog.json() if item["id"] == "otx")
    assert row["credentials"][0]["configured"] is False
    assert "无法解密" in row["credentials"][0]["problem"]
