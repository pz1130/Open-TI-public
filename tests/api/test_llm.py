import asyncio
import json
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from opti.core.secretbox import Keyring
from opti.db.models import Adjudication, AuditLog, LlmProvider, LlmSettings
from opti.pipeline import llm_runtime

pytestmark = pytest.mark.db
RING = Keyring(bytes(range(32)))
KEY = "sk-" + "api-" + "abcdefghijklmnopWXYZ"
ANSWER = '{"is_about_org": "yes", "category": "brand_mention", "confidence": 0.9, "rationale": "r", "summary": "s"}'
DEEPSEEK = {"name": "DeepSeek", "preset": "deepseek", "base_url": "https://api.deepseek.com/v1",
            "model": "deepseek-chat", "api_key": KEY}  # fmt: skip
LOCAL = {
    "name": "Local",
    "preset": "selfhosted",
    "base_url": "http://vllm:8000/v1",
    "model": "qwen",
}
SETTINGS = {"enabled": True, "primary_id": None, "backup_id": None, "gray_zone_low": 30,
            "gray_zone_high": 70, "max_per_run": 20, "max_attempts": 3, "max_wait_minutes": 30,
            "summary_language": "Chinese"}  # fmt: skip


def _deps(api: Any) -> Any:
    return api.app.state.deps


async def _admin(
    api: Any, make_user: Any, login: Any, *, ring: Keyring | None = RING
) -> httpx.AsyncClient:
    _deps(api).keyring = ring
    await make_user("ops", ("platform_admin",))
    return await login("ops")


async def _audit(api: Any) -> list[AuditLog]:
    async with api.sessions() as s:
        return list((await s.scalars(select(AuditLog).order_by(AuditLog.id))).all())


async def test_permissions(api: Any, make_user: Any, login: Any) -> None:
    await make_user()  # analyst
    await make_user("aud", ("auditor",))
    alice, aud = await login(), await login("aud")
    assert (await alice.get("/api/v1/llm/settings")).status_code == 403
    assert (await aud.get("/api/v1/llm/settings")).status_code == 200
    assert (await aud.get("/api/v1/llm/providers")).json() == []
    assert len((await aud.get("/api/v1/llm/presets")).json()) == 18
    assert (await aud.put("/api/v1/llm/settings", json=SETTINGS)).status_code == 403
    assert (await aud.post("/api/v1/llm/providers", json=LOCAL)).status_code == 403


async def test_create_keeps_key_write_only(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login)
    r = await ops.post(
        "/api/v1/llm/providers",
        json={**DEEPSEEK, "proxy": "socks5://u:" + "pw" + "@px.internal:1080"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_key_set"] and body["api_key_hint"] == "WXYZ" and body["group"] == "domestic"
    assert body["proxy_hint"] == "socks5://px.internal:1080" and body["in_use"] is None
    listed = (await ops.get("/api/v1/llm/providers")).text
    for blob in (r.text, listed, json.dumps([a.detail for a in await _audit(api)])):
        assert KEY not in blob and "pw@" not in blob
    async with api.sessions() as s:
        row = await s.scalar(select(LlmProvider))
        assert (
            row is not None and row.api_key_enc is not None and KEY.encode() not in row.api_key_enc
        )
        assert RING.decrypt(row.api_key_enc, aad=llm_runtime.aad(row.id, "api_key")) == KEY
    actions = [a.action for a in await _audit(api) if a.action.startswith("llm.")]
    assert actions == ["llm.provider.create", "llm.provider.key_set", "llm.provider.proxy_set"]


async def test_create_validation(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login, ring=None)
    assert (await ops.post("/api/v1/llm/providers", json=DEEPSEEK)).status_code == 409  # 没有主密钥
    _deps(api).keyring = RING
    bad = [
        {**DEEPSEEK, "preset": "nope"},
        {**DEEPSEEK, "base_url": "http://api.deepseek.com/v1"},
        {
            **DEEPSEEK,
            "preset": "azure_openai",
            "base_url": "https://{resource}.openai.azure.com/openai/v1",
        },
        {**DEEPSEEK, "proxy": "ftp://p:21"},
        {**DEEPSEEK, "api_key": "has space"},
        {**DEEPSEEK, "temperature": 3},
        {**DEEPSEEK, "extra": 1},
    ]
    for body in bad:
        assert (await ops.post("/api/v1/llm/providers", json=body)).status_code == 422, body
    invalid_key = "key with spaces and private token"
    rejected = await ops.post("/api/v1/llm/providers", json={**DEEPSEEK, "api_key": invalid_key})
    assert rejected.status_code == 422 and invalid_key not in rejected.text
    # 非 ASCII 字符（如粘贴时混入的中文）放不进 HTTP 请求头：保存时就拒绝，而不是测试时报 500
    non_ascii = "sk-" + "abc中def0123"
    for body in ({**DEEPSEEK, "api_key": non_ascii}, {**DEEPSEEK, "api_key": "sk-" + "tab\there"}):
        rejected = await ops.post("/api/v1/llm/providers", json=body)
        assert rejected.status_code == 422 and non_ascii not in rejected.text
    invalid_proxy = "https://user:private-token@proxy.example/invalid-path"
    rejected = await ops.post("/api/v1/llm/providers", json={**DEEPSEEK, "proxy": invalid_proxy})
    assert rejected.status_code == 422 and "private-token" not in rejected.text
    assert (
        await ops.post("/api/v1/llm/providers", json=LOCAL)
    ).status_code == 201  # 本地允许 http、无密钥
    assert (await ops.post("/api/v1/llm/providers", json=LOCAL)).status_code == 409  # 重名


async def test_patch_tri_state(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login)
    pid = (await ops.post("/api/v1/llm/providers", json=DEEPSEEK)).json()["id"]
    url = f"/api/v1/llm/providers/{pid}"
    r = await ops.patch(url, json={"model": "deepseek-reasoner", "temperature": None})
    assert r.status_code == 200 and r.json()["api_key_hint"] == "WXYZ"  # 缺省：密钥不变
    assert r.json()["model"] == "deepseek-reasoner" and r.json()["temperature"] is None
    assert (await ops.patch(url, json={"api_key": "sk-" + "new-key-0000ABCD"})).json()[
        "api_key_hint"
    ] == "ABCD"
    assert (await ops.patch(url, json={"name": None})).status_code == 422
    assert (await ops.patch(url, json={"preset": "openai"})).status_code == 422
    cleared = (await ops.patch(url, json={"api_key": None})).json()
    assert not cleared["api_key_set"] and cleared["api_key_hint"] is None
    actions = [a.action for a in await _audit(api) if a.action.startswith("llm.")]
    assert (
        actions.count("llm.provider.key_set") == 2 and actions.count("llm.provider.key_clear") == 1
    )
    update = next(a for a in await _audit(api) if a.action == "llm.provider.update")
    assert update.detail["changes"]["model"] == ["deepseek-chat", "deepseek-reasoner"]
    assert (await ops.patch("/api/v1/llm/providers/999", json={"model": "x"})).status_code == 404


async def test_settings_rules_and_in_use(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login)
    got = (await ops.get("/api/v1/llm/settings")).json()
    assert got["enabled"] is False and got["primary_id"] is None and got["updated_at"] is None
    p = (await ops.post("/api/v1/llm/providers", json=DEEPSEEK)).json()["id"]
    b = (await ops.post("/api/v1/llm/providers", json=LOCAL)).json()["id"]
    nokey = (
        await ops.post("/api/v1/llm/providers", json={**DEEPSEEK, "name": "NoKey", "api_key": None})
    ).json()["id"]
    for body in ({**SETTINGS}, {**SETTINGS, "primary_id": p, "backup_id": p},
                 {**SETTINGS, "primary_id": 999}, {**SETTINGS, "primary_id": nokey},
                 {**SETTINGS, "primary_id": None, "backup_id": b, "enabled": False},
                 {**SETTINGS, "primary_id": p, "gray_zone_low": 80, "gray_zone_high": 20}):  # fmt: skip
        assert (await ops.put("/api/v1/llm/settings", json=body)).status_code == 422, body
    assert got["code_enabled"] is False
    ok = await ops.put("/api/v1/llm/settings", json={**SETTINGS, "primary_id": p, "backup_id": b})
    assert ok.status_code == 200 and ok.json()["enabled"] and ok.json()["updated_at"]
    assert ok.json()["code_enabled"] is False  # 旧客户端不带该字段：默认关闭
    code = {**SETTINGS, "primary_id": p, "backup_id": b, "code_enabled": True}
    assert (await ops.put("/api/v1/llm/settings", json=code)).json()["code_enabled"] is True
    assert (await ops.get("/api/v1/llm/settings")).json()["code_enabled"] is True
    bad = {**code, "code_enabled": "yes"}
    assert (await ops.put("/api/v1/llm/settings", json=bad)).status_code == 422
    providers = {x["id"]: x for x in (await ops.get("/api/v1/llm/providers")).json()}
    assert providers[p]["in_use"] == "primary" and providers[b]["in_use"] == "backup"
    assert (await ops.delete(f"/api/v1/llm/providers/{p}")).status_code == 409
    assert (
        await ops.patch(f"/api/v1/llm/providers/{p}", json={"api_key": None})
    ).status_code == 422
    await ops.put("/api/v1/llm/settings", json={**SETTINGS, "enabled": False})
    assert (await ops.delete(f"/api/v1/llm/providers/{p}")).status_code == 204
    update = [a for a in await _audit(api) if a.action == "llm.settings.update"]
    assert len(update) == 3 and update[0].detail["changes"]["enabled"] == [False, True]
    assert update[1].detail["changes"] == {"code_enabled": [False, True]}


async def test_concurrent_first_settings_save(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login)
    responses = await asyncio.gather(
        ops.put("/api/v1/llm/settings", json={**SETTINGS, "enabled": False}),
        ops.put("/api/v1/llm/settings", json={**SETTINGS, "enabled": False}),
    )
    assert [r.status_code for r in responses] == [200, 200]
    async with api.sessions() as s:
        assert len((await s.scalars(select(LlmSettings))).all()) == 1


async def test_models_and_test_endpoints(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login)
    seen: list[httpx.Request] = []
    mode = {"chat": "ok"}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/models"):
            return httpx.Response(
                200, json={"data": [{"id": "deepseek-reasoner"}, {"id": "deepseek-chat"}]}
            )
        if mode["chat"] == "401":
            return httpx.Response(401, json={"error": f"bad key {KEY}"})
        return httpx.Response(200, json={"choices": [{"message": {"content": ANSWER}}]})

    _deps(api).llm_transport = httpx.MockTransport(handler)
    pid = (await ops.post("/api/v1/llm/providers", json=DEEPSEEK)).json()["id"]
    r = await ops.post(f"/api/v1/llm/providers/{pid}/models")
    assert r.status_code == 200 and r.json() == {"models": ["deepseek-chat", "deepseek-reasoner"]}
    t = (await ops.post(f"/api/v1/llm/providers/{pid}/test")).json()
    assert t["ok"] and t["verdict"] == "yes" and t["error"] is None and t["latency_ms"] >= 0
    assert seen[-1].headers["authorization"] == f"Bearer {KEY}"
    mode["chat"] = "401"
    t = (await ops.post(f"/api/v1/llm/providers/{pid}/test")).json()
    assert not t["ok"] and "401" in t["error"] and KEY not in json.dumps(t)
    row = (await ops.get("/api/v1/llm/providers")).json()[0]
    assert row["last_test_ok"] is False and "401" in row["last_test_error"]
    azure = await ops.post("/api/v1/llm/providers", json={**DEEPSEEK, "name": "Az", "preset": "azure_openai",
                                                           "base_url": "https://res.openai.azure.com/openai/v1"})  # fmt: skip
    assert (await ops.post(f"/api/v1/llm/providers/{azure.json()['id']}/models")).status_code == 409
    nokey = (
        await ops.post("/api/v1/llm/providers", json={**DEEPSEEK, "name": "NoKey", "api_key": None})
    ).json()
    t = (await ops.post(f"/api/v1/llm/providers/{nokey['id']}/test")).json()
    assert not t["ok"] and "缺少 API 密钥" in t["error"]
    actions = [a.action for a in await _audit(api) if a.action.startswith("llm.")]
    assert actions.count("llm.provider.test") == 3 and actions.count("llm.provider.models") == 1
    assert all(KEY not in json.dumps(a.detail) for a in await _audit(api))


async def test_minimax_legacy_provider_works_without_reentering_key(
    api: Any,
    make_user: Any,
    login: Any,
) -> None:
    ops = await _admin(api, make_user, login)
    legacy_url = "https://api.minimaxi.com/v1"
    canonical_url = "https://api.minimax.cn/anthropic/v1"
    created = await ops.post(
        "/api/v1/llm/providers",
        json={
            **DEEPSEEK,
            "name": "MiniMax",
            "preset": "minimax",
            "base_url": legacy_url,
            "model": "MiniMax-M2.7",
            "temperature": 0,
            "json_mode": True,
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["base_url"] == canonical_url
    pid = created.json()["id"]
    # 模拟升级前已保存的记录；运行和读取都应兼容，无需改写密文或重新保存供应商。
    async with api.sessions.begin() as s:
        row = await s.get(LlmProvider, pid)
        assert row is not None
        row.base_url = legacy_url
        encrypted_key = row.api_key_enc
    listed = (await ops.get("/api/v1/llm/providers")).json()[0]
    assert listed["base_url"] == canonical_url and listed["api_key_set"]
    assert listed["model"] == "MiniMax-M2.7" and listed["temperature"] == 0

    async with api.sessions() as s:
        row = await s.get(LlmProvider, pid)
        assert row is not None and row.api_key_enc == encrypted_key and row.base_url == legacy_url
        spec = llm_runtime.spec_for(row, RING)
        assert (
            spec.protocol == "anthropic" and spec.base_url == canonical_url and spec.api_key == KEY
        )

    seen: list[httpx.Request] = []
    fail = [False]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert str(request.url) == canonical_url + "/messages"
        assert request.headers["authorization"] == f"Bearer {KEY}"
        body = json.loads(request.content)
        assert body["model"] == "MiniMax-M2.7" and body["max_tokens"] == 8192
        assert body["temperature"] == 0 and "response_format" not in body
        if fail[0]:
            return httpx.Response(401, json={"error": {"message": KEY}})
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "thinking", "thinking": "private reasoning"},
                    {"type": "text", "text": ANSWER},
                ],
                "stop_reason": "end_turn",
            },
        )

    _deps(api).llm_transport = httpx.MockTransport(handler)
    tested = (await ops.post(f"/api/v1/llm/providers/{pid}/test")).json()
    assert tested["ok"] and tested["verdict"] == "yes"
    assert (await ops.post(f"/api/v1/llm/providers/{pid}/models")).status_code == 409
    assert len(seen) == 1  # 不尝试文档中未提供的 /models 接口
    fail[0] = True
    tested = (await ops.post(f"/api/v1/llm/providers/{pid}/test")).json()
    assert not tested["ok"] and "HTTP 401" in tested["error"] and "站点不匹配" in tested["error"]
    listed = (await ops.get("/api/v1/llm/providers")).json()[0]
    assert listed["last_test_error"] == tested["error"]
    for blob in (
        json.dumps(listed),
        json.dumps(tested),
        json.dumps([a.detail for a in await _audit(api)]),
    ):
        assert KEY not in blob and "private reasoning" not in blob

    saved = await ops.patch(
        f"/api/v1/llm/providers/{pid}",
        json={
            "base_url": "https://api.minimax.io/anthropic",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["base_url"] == "https://api.minimax.io/anthropic/v1"
    assert saved.json()["model"] == "MiniMax-M2.7" and saved.json()["api_key_set"]


async def test_status(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    ops = await _admin(api, make_user, login, ring=None)
    got = (await ops.get("/api/v1/llm/status")).json()
    assert got == {
        "encryption_key": False,
        "problem": None,
        "queue": 0,
        "done_24h": 0,
        "failed_24h": 0,
        "worker_problem": None,
        "worker_checked_at": None,
    }
    seeded = await seed_alert()
    async with api.sessions.begin() as s:
        now = api.clock()
        s.add(
            Adjudication(
                finding_id=seeded.finding_id, status="pending", created_at=now, updated_at=now
            )
        )
        s.add(
            Adjudication(
                finding_id=seeded.finding_id, status="done", created_at=now, updated_at=now
            )
        )
    got = (await ops.get("/api/v1/llm/status")).json()
    assert (got["queue"], got["done_24h"], got["failed_24h"]) == (1, 1, 0)


async def test_validation_errors_explain_without_echoing_input(
    api: Any, make_user: Any, login: Any
) -> None:
    ops = await _admin(api, make_user, login)
    r = await ops.put("/api/v1/llm/settings", json=SETTINGS)  # 启用但没有主用
    assert r.status_code == 422
    assert isinstance(r.json()["detail"], str) and "primary provider" in r.json()["detail"]
    secret = "sk-" + "abc中def0123"
    r = await ops.post("/api/v1/llm/providers", json={**DEEPSEEK, "api_key": secret, "x": 1})
    detail = r.json()["detail"]
    assert r.status_code == 422 and "api_key" in detail and "x" in detail
    assert secret not in r.text and "abc" not in r.text  # 不回显提交的值


async def test_status_shows_worker_problem(api: Any, make_user: Any, login: Any) -> None:
    ops = await _admin(api, make_user, login)
    p = (await ops.post("/api/v1/llm/providers", json=DEEPSEEK)).json()["id"]
    await ops.put("/api/v1/llm/settings", json={**SETTINGS, "primary_id": p})
    async with api.sessions() as s, s.begin():
        await llm_runtime.report(s, await llm_runtime.load(s, None), now=api.clock())
    got = (await ops.get("/api/v1/llm/status")).json()
    assert got["problem"] is None  # API 进程有主密钥
    assert "凭据加密主密钥" in got["worker_problem"] and got["worker_checked_at"]
