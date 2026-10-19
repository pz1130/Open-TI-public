import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import select

from opti.api.oidc.runtime import ConfigBoundOidc
from opti.configs import secrets
from opti.configs.runtime import ConfigRuntime
from opti.core.secretbox import Keyring, generate_key, master_key_path
from opti.db.models import AuditLog
from opti.sdk.http import RateLimitedHttpClient
from tests.api.conftest import ApiWorld

pytestmark = pytest.mark.db


@pytest.fixture
def uninitialized(api: ApiWorld, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ApiWorld:
    monkeypatch.delenv("OPTI_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("OPTI_ENCRYPTION_KEY_PREVIOUS", raising=False)
    api.deps.settings = replace(api.deps.settings, state_dir=tmp_path)
    return api


async def test_initialize_then_save_github_and_reload_worker(
    uninitialized, make_user, login
) -> None:
    api = uninitialized
    await make_user("ops", ("platform_admin",))
    c = await login("ops")
    worker = await ConfigRuntime.start(api.deps.settings, api.sessions, process="worker@test")
    assert worker.keyring is None
    created = await c.post("/api/v1/admin/master-key", json={})
    assert created.status_code == 200, created.text
    key = created.json()["backup_key"]
    assert created.headers["cache-control"] == "no-store"
    status = await c.get("/api/v1/admin/master-key")
    assert status.json() == {
        "configured": True,
        "source": "managed",
        "has_encrypted_credentials": False,
    }
    assert key not in status.text
    token = "github-test-token-12345678"
    saved = await c.put(
        "/api/v1/connectors/github_code/config",
        json={
            "enabled": True,
            "plan": "free",
            "config": {},
            "secrets": {"token": token},
            "schedule": "0 */6 * * *",
        },
    )
    assert saved.status_code == 200, saved.text
    assert key not in saved.text and token not in saved.text
    assert await worker.refresh()
    assert worker.snapshot.secrets("connectors")["github_code:token"] == token
    restarted = await ConfigRuntime.start(api.deps.settings, api.sessions)
    assert restarted.snapshot.secrets("connectors")["github_code:token"] == token
    overwritten = await c.post("/api/v1/admin/master-key", json={})
    assert overwritten.status_code == 409
    assert master_key_path(api.deps.settings.state_dir).read_text().strip() == key
    async with api.sessions() as s:
        audits = [(a.action, a.detail) for a in await s.scalars(select(AuditLog))]
    assert key not in json.dumps(audits) and token not in json.dumps(audits)
    assert any(a == "system.master_key_initialized" for a, _ in audits)


async def test_existing_credentials_require_original_key(uninitialized, make_user, login) -> None:
    api = uninitialized
    original = generate_key()
    ring = Keyring.from_env({"OPTI_ENCRYPTION_KEY": original})
    async with api.sessions.begin() as s:
        await secrets.write(
            s,
            "connectors",
            {"github_code:token": "original-token"},
            keyring=ring,
            user="test",
            now=api.clock(),
        )
    await make_user("ops", ("platform_admin",))
    c = await login("ops")
    assert (await c.post("/api/v1/admin/master-key", json={})).status_code == 409
    wrong = generate_key()
    rejected = await c.post("/api/v1/admin/master-key", json={"key": wrong})
    assert rejected.status_code == 422 and wrong not in rejected.text
    assert not master_key_path(api.deps.settings.state_dir).exists()
    imported = await c.post("/api/v1/admin/master-key", json={"key": original})
    assert imported.status_code == 200 and imported.json()["backup_key"] is None
    assert original not in imported.text


async def test_permissions_validation_and_concurrent_initialization(
    uninitialized, make_user, login
) -> None:
    await make_user("reader", ("viewer",))
    c = await login("reader")
    assert (await c.get("/api/v1/admin/master-key")).status_code == 403
    assert (await c.post("/api/v1/admin/master-key", json={})).status_code == 403
    await make_user("ops", ("platform_admin",))
    admin = await login("ops")
    secret = "invalid-sensitive-key"
    r = await admin.post("/api/v1/admin/master-key", json={"key": secret, "unknown": secret})
    assert r.status_code == 422 and secret not in r.text
    responses = await asyncio.gather(
        *[admin.post("/api/v1/admin/master-key", json={}) for _ in range(2)]
    )
    assert sorted(r.status_code for r in responses) == [200, 409]


async def test_identity_settings_apply_to_login_and_keep_secret_out_of_history(
    uninitialized, make_user, login
) -> None:
    api = uninitialized
    http = RateLimitedHttpClient()
    api.deps.oidc_source = ConfigBoundOidc(lambda: api.deps.config.snapshot, http)
    await make_user("ops", ("platform_admin",))
    c = await login("ops")
    await c.post("/api/v1/admin/master-key", json={})
    cfg = (await c.get("/api/v1/config/identity")).json()["data"]
    cfg.update(
        session_hours=2,
        cookie_secure=False,
        enabled=True,
        provider="generic",
        issuer="https://login.example",
        client_id="application",
        local_login=False,
        role_mapping={"platform_admin": ["TI-Admins"]},
    )
    secret = "identity-client-secret"
    saved = await c.put(
        "/api/v1/config/identity",
        json={"data": cfg, "base_version": 0, "secrets": {"client_secret": secret}},
    )
    assert saved.status_code == 200, saved.text
    assert not (await c.get("/api/v1/auth/providers")).json()["local"]
    assert (await c.get("/api/v1/auth/providers")).json()["oidc"]
    assert (
        await c.post("/api/v1/auth/login", json={"username": "ops", "password": "irrelevant"})
    ).status_code == 403
    assert secret not in (await c.get("/api/v1/config/identity/revisions/1")).text
    cfg.update(enabled=False)
    rejected = await c.put("/api/v1/config/identity", json={"data": cfg, "base_version": 1})
    assert rejected.status_code == 422
    assert api.deps.config.snapshot.identity.enabled
    await http.aclose()


async def test_operation_validation_and_history(uninitialized, make_user, login) -> None:
    await make_user("ops", ("platform_admin",))
    c = await login("ops")
    before = (await c.get("/api/v1/config/operations")).json()
    data = before["data"]
    data["risk"]["high_score"] = 30
    assert (
        await c.put("/api/v1/config/operations", json={"data": data, "base_version": 0})
    ).status_code == 422
    data["risk"]["high_score"] = 70
    data["schedules"]["recheck_watchlist"] = "*/20 * * * *"
    saved = await c.put("/api/v1/config/operations", json={"data": data, "base_version": 0})
    assert saved.status_code == 200, saved.text
    assert uninitialized.deps.config.snapshot.operations.risk.high_score == 70
    assert (await c.get("/api/v1/config/operations/revisions")).json()[0]["version"] == 1


async def test_web_master_key_enables_llm_without_restart(uninitialized, make_user, login) -> None:
    api = uninitialized
    await make_user("ops", ("platform_admin",))
    client = await login("ops")
    worker = await ConfigRuntime.start(api.deps.settings, api.sessions, process="worker@test")
    provider = {
        "name": "DeepSeek",
        "preset": "deepseek",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "api_key": "test-model-secret-12345678",
    }
    refused = await client.post("/api/v1/llm/providers", json=provider)
    assert refused.status_code == 409 and "管理员" in refused.json()["detail"]
    await client.post("/api/v1/admin/master-key", json={})
    saved = await client.post("/api/v1/llm/providers", json=provider)
    assert saved.status_code == 201, saved.text
    assert provider["api_key"] not in saved.text
    assert (await client.get("/api/v1/llm/status")).json()["encryption_key"]
    await worker.refresh()
    assert worker.keyring is not None
    from opti.db.models import LlmProvider
    from opti.pipeline.llm_runtime import spec_for

    async with api.sessions() as session:
        row = await session.get(LlmProvider, saved.json()["id"])
        assert spec_for(row, worker.keyring).api_key == provider["api_key"]
