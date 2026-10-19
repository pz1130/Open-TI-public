"""单点登录接口（设计文档 15）：发起与回调都是浏览器顶层跳转，失败时跳回登录页并带上错误代码。"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse

from opti.api import security
from opti.api.deps import COOKIE, client_ip, get_deps, record
from opti.api.oidc import service as oidc_service
from opti.api.oidc.client import Identity, OidcError
from opti.api.schemas import AuthProviders

router = APIRouter(tags=["auth"])
BINDING_COOKIE = "opti_oidc"
BINDING_PATH = "/api/v1/auth/oidc"


def _fail(code: str) -> RedirectResponse:
    return RedirectResponse(f"/?login_error={code}", status_code=303)


def _clear_binding(resp: Response, secure: bool) -> Response:
    resp.delete_cookie(
        BINDING_COOKIE, path=BINDING_PATH, httponly=True, samesite="lax", secure=secure
    )
    return resp


@router.get("/auth/providers")
async def providers(request: Request) -> AuthProviders:
    deps = get_deps(request)
    return AuthProviders(
        local=deps.identity.local_login,
        oidc=deps.oidc is not None,
        oidc_label=deps.oidc.cfg.label if deps.oidc is not None else "",
    )


@router.get("/auth/oidc/start", response_class=RedirectResponse, status_code=303)
async def oidc_start(
    request: Request, next_path: Annotated[str | None, Query(alias="next", max_length=512)] = None
) -> Response:
    deps = get_deps(request)
    if deps.oidc is None:
        raise HTTPException(404, "single sign-on is not enabled")
    now = deps.clock()
    ip = client_ip(request) or "unknown"
    wait = deps.oidc_starts.retry_after(ip, now)
    if wait is not None:
        raise HTTPException(429, "too many login attempts", headers={"Retry-After": str(wait)})
    deps.oidc_starts.hit(ip, now)
    try:
        provider = await deps.oidc.provider()
    except OidcError:
        return _fail("unavailable")
    async with deps.sessions.begin() as s:
        started = await oidc_service.begin(s, now=now, next_path=next_path)
    url = deps.oidc.authorize_url(
        provider, state=started.state, nonce=started.nonce, challenge=started.challenge
    )
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(
        BINDING_COOKIE, started.binding, max_age=int(oidc_service.LOGIN_TTL.total_seconds()),
        httponly=True, secure=deps.identity.cookie_secure, samesite="lax", path=BINDING_PATH,
    )  # fmt: skip
    return resp


@router.get("/auth/oidc/callback", response_class=RedirectResponse, status_code=303)
async def oidc_callback(
    request: Request,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=512)] = None,
    error: Annotated[str | None, Query(max_length=200)] = None,
) -> Response:
    deps = get_deps(request)
    oidc = deps.oidc
    if oidc is None:
        raise HTTPException(404, "single sign-on is not enabled")
    secure = deps.identity.cookie_secure
    now = deps.clock()
    # 先在独立事务中作废登录状态并提交：即使后续失败，同一个 state 也不能再用
    async with deps.sessions.begin() as s:
        pending = await oidc_service.finish(
            s, state=state or "", binding=request.cookies.get(BINDING_COOKIE), now=now
        )
        if pending is None:
            await record(s, request, "oidc", "auth.oidc_denied", detail={"reason": "state"})
        elif error or not code:
            await record(
                s,
                request,
                "oidc",
                "auth.oidc_denied",
                detail={"reason": "cancelled", "error": (error or "")[:100]},
            )
    if pending is None:
        return _clear_binding(_fail("state"), secure)
    if error or not code:
        return _clear_binding(_fail("cancelled"), secure)

    ident: Identity | None = None
    try:
        provider = await oidc.provider()
        claims = await oidc.validate(
            provider, await oidc.exchange(provider, code, pending.code_verifier), pending.nonce
        )
        ident = oidc.identity(claims)
        async with deps.sessions.begin() as s:
            user, change = await oidc_service.upsert_user(s, oidc.cfg, ident, now)
            ttl = timedelta(hours=deps.identity.session_hours)
            token = await security.create_session(
                s, user, now=now, ttl=ttl, ip=client_ip(request), method="oidc"
            )
            if "roles_before" in change and change["roles_before"] != change["roles"]:
                await record(s, request, user.username, "user.roles_sync", target_type="app_user",
                             target_id=user.username, detail=change)  # fmt: skip
            detail: dict[str, Any] = {"method": "oidc", "roles": change["roles"]}
            if change.get("created"):
                detail["created"] = True
            await record(s, request, user.username, "auth.login", detail=detail)
    except OidcError as e:
        async with deps.sessions.begin() as s:
            await record(
                s, request, ident.username if ident is not None else "oidc", "auth.oidc_denied",
                detail={"reason": e.code, "message": str(e)[:300]},
            )  # fmt: skip
        return _clear_binding(_fail(e.code), secure)
    resp = RedirectResponse(pending.next_path, status_code=303)
    resp.set_cookie(
        COOKIE, token, max_age=int(ttl.total_seconds()), httponly=True, secure=secure,
        samesite="strict", path="/",
    )  # fmt: skip
    return _clear_binding(resp, secure)
