import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import func, select

from opti.api import security
from opti.api.oidc.client import OidcClient
from opti.api.oidc.config import OidcConfig
from opti.api.oidc.service import safe_next
from opti.api.oidc.testing import FakeIdp
from opti.db.models import ApiSession, AppUser, AuditLog
from opti.sdk.testing import make_http

pytestmark = pytest.mark.db
PASSWORD = "correct horse battery staple"


def _setup(api: Any, **cfg: Any) -> FakeIdp:
    idp = FakeIdp()
    config = OidcConfig.model_validate(
        {
            "enabled": True, "issuer": idp.issuer, "client_id": "opti", "label": "Example SSO",
            "post_logout_redirect_uri": "http://testserver/",
            "role_mapping": {"analyst": ["opti-analysts"], "responder": ["opti-responders"]}, **cfg,
        }
    )  # fmt: skip
    api.app.state.deps.oidc = OidcClient(
        config,
        make_http(idp.handler),
        "secret-1",
        redirect_uri="http://testserver/api/v1/auth/oidc/callback",
    )
    return idp


def _browser(api: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app),
        base_url="http://testserver",
        headers={"X-Requested-With": "opti"},
    )


async def _start(browser: httpx.AsyncClient, next_path: str = "/alerts/7") -> dict[str, str]:
    r = await browser.get("/api/v1/auth/oidc/start", params={"next": next_path})
    assert r.status_code == 303, r.text
    return {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}


async def _login(
    idp: FakeIdp, browser: httpx.AsyncClient, *, sub: str = "u-1", groups: tuple[str, ...] = ("opti-analysts",),
    username: str | None = None, next_path: str = "/alerts/7", **token_kw: Any,
) -> httpx.Response:  # fmt: skip
    q = await _start(browser, next_path)
    code = secrets.token_hex(8)
    idp.issue(
        code,
        challenge=q["code_challenge"],
        nonce=q["nonce"],
        sub=sub,
        groups=groups,
        username=username,
        **token_kw,
    )
    return await browser.get(
        "/api/v1/auth/oidc/callback", params={"code": code, "state": q["state"]}
    )


async def _audit(api: Any, action: str) -> list[dict[str, Any]]:
    async with api.sessions() as s:
        rows = (
            await s.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id))
        ).all()
    return [{"actor": r.actor, **r.detail} for r in rows]


async def _sessions(api: Any) -> int:
    async with api.sessions() as s:
        return int(await s.scalar(select(func.count()).select_from(ApiSession)) or 0)


async def test_providers_login_and_logout(api: Any) -> None:
    idp = _setup(api)
    async with _browser(api) as b:
        assert (await b.get("/api/v1/auth/providers")).json() == {
            "local": True,
            "oidc": True,
            "oidc_label": "Example SSO",
        }
        r = await _login(idp, b)
        assert r.status_code == 303 and r.headers["location"] == "/alerts/7"
        assert b.cookies.get("opti_session") and not b.cookies.get("opti_oidc")
        me = (await b.get("/api/v1/auth/me")).json()
        assert (
            me["username"] == "u-1@example.org"
            and me["roles"] == ["analyst"]
            and me["auth_source"] == "oidc"
        )
        assert idp.token_requests[0]["client_secret"] == "secret-1"
        async with api.sessions() as s:
            assert await s.scalar(select(ApiSession.auth_method)) == "oidc"
        out = await b.post("/api/v1/auth/logout")
        assert out.status_code == 200
        assert out.json()["logout_url"] == (
            f"{idp.issuer}/protocol/openid-connect/logout?client_id=opti"
            "&post_logout_redirect_uri=http%3A%2F%2Ftestserver%2F"
        )
        assert (await b.get("/api/v1/auth/me")).status_code == 401
    async with api.sessions() as s:
        user = await s.scalar(select(AppUser).where(AppUser.username == "u-1@example.org"))
        assert user is not None and user.auth_source == "oidc" and user.oidc_subject == "u-1"
        assert user.password_hash == "!" and user.email == "u-1@example.org"
    assert await _sessions(api) == 0  # 登出后会话已删除
    [login] = await _audit(api, "auth.login")
    assert login == {
        "actor": "u-1@example.org",
        "method": "oidc",
        "roles": ["analyst"],
        "created": True,
    }


async def test_state_binding_and_replay(api: Any) -> None:
    idp = _setup(api)
    async with _browser(api) as victim, _browser(api) as attacker:
        q = await _start(attacker)  # 攻击者自己发起登录，把回调链接发给受害者
        code = secrets.token_hex(8)
        idp.issue(code, challenge=q["code_challenge"], nonce=q["nonce"], sub="attacker")
        r = await victim.get(
            "/api/v1/auth/oidc/callback", params={"code": code, "state": q["state"]}
        )
        assert r.headers["location"] == "/?login_error=state"  # 受害者浏览器没有绑定 Cookie
        r = await attacker.get(
            "/api/v1/auth/oidc/callback", params={"code": code, "state": q["state"]}
        )
        assert r.headers["location"] == "/?login_error=state"  # 状态已作废，不能再用

        q = await _start(victim)
        api.clock.now += timedelta(minutes=11)
        r = await victim.get(
            "/api/v1/auth/oidc/callback", params={"code": "x", "state": q["state"]}
        )
        assert r.headers["location"] == "/?login_error=state"  # 已过期

        q = await _start(victim)
        r = await victim.get(
            "/api/v1/auth/oidc/callback", params={"error": "access_denied", "state": q["state"]}
        )
        assert r.headers["location"] == "/?login_error=cancelled"
        r = await victim.get("/api/v1/auth/oidc/callback")
        assert r.headers["location"] == "/?login_error=state"
    assert await _sessions(api) == 0
    reasons = [d["reason"] for d in await _audit(api, "auth.oidc_denied")]
    assert reasons == ["state", "state", "state", "cancelled", "state"]


def test_safe_next() -> None:
    for bad in ["https://evil.example", "//evil.example", "/\\evil.example", "/api/v1/auth/logout",
                "evil", "", None, "/a\r\nSet-Cookie: x=1", "/a\x00", "/a\x7f",
                "/" + "a" * 600]:  # fmt: skip
        assert safe_next(bad) == "/", bad
    assert safe_next("/alerts/7?tab=evidence") == "/alerts/7?tab=evidence"


async def test_open_redirect_is_neutralized(api: Any) -> None:
    idp = _setup(api)
    async with _browser(api) as b:
        r = await _login(idp, b, next_path="https://evil.example/phish")
        assert r.status_code == 303 and r.headers["location"] == "/"


async def test_username_conflict_and_no_password_login(api: Any, make_user: Any) -> None:
    idp = _setup(api)
    await make_user("alice", ("platform_admin",))  # 本地应急账号
    async with _browser(api) as b:
        r = await _login(idp, b, sub="idp-alice", username="alice")
        assert r.headers["location"] == "/?login_error=username_conflict"
        r = await _login(idp, b, sub="u-2", username="bob@example.org")
        assert r.headers["location"] == "/alerts/7"
        r = await b.post(
            "/api/v1/auth/login", json={"username": "bob@example.org", "password": "!"}
        )
        assert r.status_code == 401  # OIDC 账号没有可用口令
    async with api.sessions.begin() as s:
        with pytest.raises(security.UserError):
            await security.set_password(s, "bob@example.org", PASSWORD)
        alice = await s.scalar(select(AppUser).where(AppUser.username == "alice"))
        assert alice is not None and alice.auth_source == "local" and alice.oidc_subject is None
    assert [d["reason"] for d in await _audit(api, "auth.oidc_denied")] == ["username_conflict"]


async def test_roles_follow_idp_and_disabled_users_stay_out(api: Any) -> None:
    idp = _setup(api)
    async with _browser(api) as b:
        assert (await _login(idp, b, groups=("opti-analysts",))).headers["location"] == "/alerts/7"
        assert (await b.get("/api/v1/auth/me")).json()["roles"] == ["analyst"]
        assert (await _login(idp, b, groups=("opti-responders", "unrelated"))).headers[
            "location"
        ] == "/alerts/7"
        assert (await b.get("/api/v1/auth/me")).json()["roles"] == ["responder"]
        assert (await _login(idp, b, groups=())).headers["location"] == "/?login_error=no_role"
        assert (await _login(idp, b, sub="newcomer", groups=())).headers[
            "location"
        ] == "/?login_error=no_role"
    async with api.sessions.begin() as s:
        assert await s.scalar(select(AppUser).where(AppUser.oidc_subject == "newcomer")) is None
        await security.set_active(s, "u-1@example.org", False)
    async with _browser(api) as b:
        assert (await _login(idp, b)).headers["location"] == "/?login_error=disabled"
    [sync] = await _audit(api, "user.roles_sync")
    assert sync["roles_before"] == ["analyst"] and sync["roles"] == ["responder"]


async def test_idp_problems(api: Any) -> None:
    idp = _setup(api)
    async with _browser(api) as b:
        r = await _login(idp, b, aud="someone-else")
        assert r.headers["location"] == "/?login_error=id_token"
    # 发现文档的签发者与配置不符：换一个新客户端（旧客户端已缓存发现文档）
    idp2 = FakeIdp()
    idp2.discovery_overrides = {"issuer": "https://evil.example"}
    api.app.state.deps.oidc = OidcClient(
        api.app.state.deps.oidc.cfg,
        make_http(idp2.handler),
        None,
        redirect_uri="http://testserver/cb",
    )
    async with _browser(api) as b:
        r = await b.get("/api/v1/auth/oidc/start")
        assert r.status_code == 303 and r.headers["location"] == "/?login_error=unavailable"
    assert await _sessions(api) == 0


async def test_oidc_disabled(api: Any) -> None:
    async with _browser(api) as b:
        assert (await b.get("/api/v1/auth/providers")).json() == {
            "local": True,
            "oidc": False,
            "oidc_label": "",
        }
        assert (await b.get("/api/v1/auth/oidc/start")).status_code == 404
        assert (await b.get("/api/v1/auth/oidc/callback")).status_code == 404
