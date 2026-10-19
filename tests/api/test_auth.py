from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from opti.api import security
from opti.api.rbac import Perm, permissions
from opti.db.models import AppUser, AuditLog

pytestmark = pytest.mark.db
PASSWORD = "correct horse battery staple"  # 与 conftest 一致；测试文件之间不互相导入


def _anon(api: Any, *, csrf: bool = True) -> httpx.AsyncClient:
    headers = {"X-Requested-With": "opti"} if csrf else {}
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver", headers=headers
    )


async def _actions(api: Any) -> list[str]:
    async with api.sessions() as s:
        return list((await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all())


async def test_login_me_logout(api: Any, make_user: Callable[..., Awaitable[int]]) -> None:
    await make_user(roles=("analyst", "viewer"))
    async with _anon(api) as c:
        r = await c.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        assert r.status_code == 200
        cookie = r.headers["set-cookie"].lower()
        assert "opti_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        me = (await c.get("/api/v1/auth/me")).json()
        assert me["username"] == "alice" and sorted(me["roles"]) == ["analyst", "viewer"]
        assert "alerts:triage" in me["permissions"]
        r = await c.post("/api/v1/auth/logout")
        assert r.status_code == 200 and r.json() == {
            "logout_url": None
        }  # 本地口令会话没有身份提供方登出地址
        assert (await c.get("/api/v1/auth/me")).status_code == 401
    assert await _actions(api) == ["auth.login", "auth.logout"]


async def test_wrong_password_and_unknown_user(
    api: Any, make_user: Callable[..., Awaitable[int]]
) -> None:
    await make_user()
    async with _anon(api) as c:
        assert (
            await c.post("/api/v1/auth/login", json={"username": "alice", "password": "x" * 12})
        ).status_code == 401
        assert (
            await c.post("/api/v1/auth/login", json={"username": "nobody", "password": "x" * 12})
        ).status_code == 401
    assert await _actions(api) == ["auth.login_failed", "auth.login_failed"]


async def test_lockout_after_repeated_failures(
    api: Any, make_user: Callable[..., Awaitable[int]]
) -> None:
    await make_user()
    async with _anon(api) as c:
        for _ in range(security.MAX_FAILED_LOGINS):
            await c.post(
                "/api/v1/auth/login", json={"username": "alice", "password": "wrong-password!"}
            )
        r = await c.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        assert r.status_code == 401  # 锁定期内正确口令也不行
        api.clock.now += security.LOCKOUT + timedelta(seconds=1)
        assert (
            await c.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        ).status_code == 200


async def test_session_expires(
    api: Any, make_user: Callable[..., Awaitable[int]], login: Any
) -> None:
    await make_user()
    c = await login()
    assert (await c.get("/api/v1/auth/me")).status_code == 200
    api.clock.now += timedelta(hours=13)
    assert (await c.get("/api/v1/auth/me")).status_code == 401


async def test_disabled_user_loses_session(
    api: Any, make_user: Callable[..., Awaitable[int]], login: Any
) -> None:
    await make_user()
    c = await login()
    async with api.sessions.begin() as s:
        await security.set_active(s, "alice", False)
    assert (await c.get("/api/v1/auth/me")).status_code == 401


async def test_write_requests_require_csrf_header(
    api: Any, make_user: Callable[..., Awaitable[int]], login: Any
) -> None:
    await make_user()
    c = await login()
    r = await c.post("/api/v1/auth/logout", headers={"X-Requested-With": ""})
    assert r.status_code == 403
    assert (await c.get("/api/v1/auth/me")).status_code == 200  # 会话仍有效


async def test_password_rules(api: Any) -> None:
    async with api.sessions.begin() as s:
        with pytest.raises(security.UserError, match="12"):
            await security.create_user(
                s, username="bob", password="short", roles=["analyst"], now=api.clock()
            )
        with pytest.raises(security.UserError, match="角色"):
            await security.create_user(
                s, username="bob", password=PASSWORD, roles=["root"], now=api.clock()
            )
        await security.create_user(
            s, username="bob", password=PASSWORD, roles=["viewer"], now=api.clock()
        )
        with pytest.raises(security.UserError, match="已存在"):
            await security.create_user(
                s, username="bob", password=PASSWORD, roles=["viewer"], now=api.clock()
            )
        user = await s.scalar(select(AppUser).where(AppUser.username == "bob"))
        assert user is not None and PASSWORD not in user.password_hash


def test_permissions_by_role() -> None:
    assert Perm.ALERTS_TRIAGE in permissions(["analyst"])
    assert Perm.ALERTS_TRIAGE not in permissions(["viewer"])
    assert Perm.EVIDENCE_READ not in permissions(["viewer"])
    assert Perm.ALERTS_READ not in permissions(["platform_admin"])  # 不能看告警
    assert permissions(["auditor"]) == frozenset({Perm.AUDIT_READ, Perm.LLM_READ, Perm.CONFIG_READ})
    assert permissions(["viewer", "auditor"]) == permissions(["viewer"]) | permissions(["auditor"])
    assert permissions(["unknown-role"]) == frozenset()


async def test_password_reset_invalidates_existing_sessions(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    c = await login()
    new_password = "replacement correct horse battery"
    async with api.sessions.begin() as s:
        await security.set_password(s, "alice", new_password)
    assert (await c.get("/api/v1/auth/me")).status_code == 401
    async with _anon(api) as anon:
        assert (
            await anon.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        ).status_code == 401
        assert (
            await anon.post(
                "/api/v1/auth/login", json={"username": "alice", "password": new_password}
            )
        ).status_code == 200


async def test_secure_cookie_and_hashed_session_token(api: Any, make_user: Any) -> None:
    import hashlib
    from dataclasses import replace

    from opti.db.models import ApiSession

    await make_user()
    deps = api.app.state.deps
    deps.settings = replace(deps.settings, cookie_secure=True)
    async with _anon(api) as c:
        response = await c.post(
            "/api/v1/auth/login", json={"username": "alice", "password": PASSWORD}
        )
        assert response.status_code == 200 and "secure" in response.headers["set-cookie"].lower()
        token = response.cookies["opti_session"]
    async with api.sessions() as s:
        row = (await s.scalars(select(ApiSession))).one()
        assert row.id == hashlib.sha256(token.encode()).hexdigest() and row.id != token
        user = (await s.scalars(select(AppUser))).one()
        assert user.password_hash.startswith("$argon2id$")
