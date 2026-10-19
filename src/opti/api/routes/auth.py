from __future__ import annotations

import asyncio
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response

from opti.api import security
from opti.api.access import effective_permissions, roles_for
from opti.api.access_schemas import PasswordChangeIn
from opti.api.bootstrap import clear_bootstrap_password
from opti.api.deps import COOKIE, CurrentUser, client_ip, get_deps, record
from opti.api.oidc.client import OidcError
from opti.api.rbac import Perm
from opti.api.schemas import LoginRequest, LogoutOut, Me

router = APIRouter(tags=["auth"])


def _me(
    username: str,
    display_name: str,
    roles: list[str],
    auth_source: str,
    perms: frozenset[Perm],
    must_change_password: bool = False,
) -> Me:
    return Me(
        username=username,
        auth_source=auth_source,
        display_name=display_name,
        roles=sorted(roles),
        permissions=sorted(p.value for p in perms),
        must_change_password=must_change_password,
    )


@router.post("/auth/login")
async def login(body: LoginRequest, request: Request, response: Response) -> Me:
    deps = get_deps(request)
    now = deps.clock()
    if not deps.identity.local_login:
        raise HTTPException(403, "local login is disabled; use single sign-on")
    ip = client_ip(request) or "unknown"
    wait = deps.login_failures.retry_after(ip, now)
    if wait is not None:
        # 不做口令校验，也不写审计（被刷时不放大成数据库写入）
        raise HTTPException(
            429, "too many failed logins from this address", headers={"Retry-After": str(wait)}
        )
    ttl = timedelta(hours=deps.identity.session_hours)
    token: str | None = None
    me: Me | None = None
    # 先提交（失败计数与审计必须落库），再决定返回 401 还是 200
    async with deps.sessions.begin() as s:
        user = await security.authenticate(s, body.username, body.password, now)
        if user is None:
            await record(s, request, body.username[:100], "auth.login_failed")
        else:
            token = await security.create_session(s, user, now=now, ttl=ttl, ip=client_ip(request))
            await record(s, request, user.username, "auth.login", detail={"method": "password"})
            me = _me(
                user.username,
                user.display_name,
                roles_for(user),
                user.auth_source,
                await effective_permissions(s, user),
                user.must_change_password,
            )
    if token is None or me is None:
        deps.login_failures.hit(ip, now)
        raise HTTPException(401, "invalid credentials")
    response.set_cookie(
        COOKIE,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,
        secure=deps.identity.cookie_secure,
        samesite="strict",
        path="/",
    )
    return me


@router.post("/auth/logout")
async def logout(user: CurrentUser, request: Request, response: Response) -> LogoutOut:
    deps = get_deps(request)
    token = request.cookies.get(COOKIE, "")
    async with deps.sessions.begin() as s:
        method = await security.session_method(s, token)
        await security.end_session(s, token)
        await record(s, request, user, "auth.logout")
    response.delete_cookie(
        COOKIE, path="/", httponly=True, samesite="strict", secure=deps.identity.cookie_secure
    )
    logout_url = None
    if method == "oidc" and deps.oidc is not None:
        try:
            logout_url = deps.oidc.logout_url(await deps.oidc.provider())
        except OidcError:
            logout_url = None  # 身份提供方不可用时只结束本平台会话
    return LogoutOut(logout_url=logout_url)


@router.get("/auth/me")
async def me(user: CurrentUser) -> Me:
    return _me(
        user.username,
        user.display_name,
        list(user.roles),
        user.auth_source,
        user.perms,
        user.must_change_password,
    )


@router.post("/auth/password")
async def change_password(
    body: PasswordChangeIn, user: CurrentUser, request: Request, response: Response
) -> dict[str, bool]:
    deps = get_deps(request)
    key = f"password:{user.user_id}"
    if deps.login_failures.retry_after(key, deps.clock()) is not None:
        raise HTTPException(429, "尝试次数过多，请稍后再试")
    async with deps.sessions.begin() as s:
        account = await security._user(s, user.username, lock=True)
        if account is None or account.auth_source != "local":
            raise HTTPException(422, "单点登录账号请在身份提供方修改密码")
        current, password = (
            body.current_password.get_secret_value(),
            body.new_password.get_secret_value(),
        )

        if not await asyncio.to_thread(security.verify_password, account.password_hash, current):
            deps.login_failures.hit(key, deps.clock())
            raise HTTPException(422, "当前密码不正确")
        if current == password:
            raise HTTPException(422, "新密码不能与当前密码相同")
        await security.set_password(s, user.username, password)
        await record(
            s, request, user, "user.password", target_type="app_user", target_id=user.username
        )
    clear_bootstrap_password(deps.settings.state_dir, user.username)
    response.delete_cookie(
        COOKIE, path="/", httponly=True, samesite="strict", secure=deps.identity.cookie_secure
    )
    return {"changed": True}
