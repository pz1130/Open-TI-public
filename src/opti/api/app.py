"""研判接口应用：安全中间件、路由、前端静态文件（同源，Teams 告警链接 /alerts/{id} 直接可用）。"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope

from opti.api import VERSION
from opti.api.deps import ApiDeps, get_deps, pin_request_snapshot, reset_request_snapshot
from opti.api.routes import (
    alerts,
    audit,
    auth,
    campaigns,
    certificates,
    config,
    connectors,
    dashboard,
    documents,
    domain_keywords,
    evidence,
    export,
    exposure,
    keyword_scan,
    llm,
    oidc,
    projects,
    reports,
    rules,
    social_accounts,
    submissions,
    suppressions,
    system,
    takedowns,
    tickets,
    translation,
    users,
    watchlist,
)

CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "opti"
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; font-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
ROUTERS: list[APIRouter] = [
    takedowns.router,
    tickets.router,
    export.router,
    auth.router,
    users.router,
    oidc.router,
    dashboard.router,
    connectors.router,
    llm.router,
    alerts.router,
    campaigns.router,
    translation.router,
    evidence.router,
    exposure.router,
    domain_keywords.router,
    watchlist.router,
    certificates.router,
    social_accounts.router,
    suppressions.router,
    audit.router,
    rules.router,
    keyword_scan.router,
    config.router,
    projects.router,
    system.router,
    documents.router,
    reports.router,
    submissions.router,
]


async def _security(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    token = pin_request_snapshot(get_deps(request).config.snapshot)
    try:
        request.state.request_id = uuid.uuid4().hex
        is_api = request.url.path.startswith("/api/")
        if (
            is_api
            and request.url.path != "/api/v1/integrations/tickets"
            and request.method in WRITE_METHODS
            and request.headers.get(CSRF_HEADER) != CSRF_VALUE
        ):
            response: Response = JSONResponse(
                {"detail": f"missing {CSRF_HEADER} header"}, status_code=403
            )
        else:
            response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        response.headers["X-Request-ID"] = request.state.request_id
        if is_api:
            response.headers.setdefault("Cache-Control", "no-store")
        return response
    finally:
        reset_request_snapshot(token)


NO_CACHE = {"Cache-Control": "no-cache"}  # 入口页每次向服务器确认：发布后立即拿到新的分块清单


class HashedAssets(StaticFiles):
    """构建产物文件名带内容哈希，内容变了文件名就变，可以长期缓存。"""

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


def _mount_web(app: FastAPI, dist: Path | None) -> None:
    if dist is None or not (dist / "index.html").is_file():
        return
    root = dist.resolve()
    index = (root / "index.html").read_text(encoding="utf-8")
    if (root / "assets").is_dir():
        app.mount("/assets", HashedAssets(directory=root / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> Response:
        if path.startswith("api/") or path in {"docs", "redoc", "openapi.json"}:
            raise HTTPException(404, "not found")
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate, headers=NO_CACHE)
        return HTMLResponse(index, headers=NO_CACHE)


def _explain(exc: RequestValidationError) -> str:
    """只保留字段名与原因：默认响应会带上提交的原值（input），其中可能有 API 密钥或代理凭据。"""
    parts: list[str] = []
    for err in exc.errors():
        loc = [str(x) for x in err.get("loc", ())]
        field = ".".join(loc[1:] if loc[:1] == ["body"] else loc)
        msg = str(err.get("msg", "invalid value")).removeprefix("Value error, ")
        parts.append(f"{field}: {msg}" if field else msg)
    return "; ".join(parts)[:500] or "invalid request"


async def _validation_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, RequestValidationError)
    # 告警配置的请求体里有 Webhook 与 SMTP 口令，校验失败也不能把原值回显出去。
    if request.url.path.startswith(
        (
            "/api/v1/llm/",
            "/api/v1/config/",
            "/api/v1/admin/",
            "/api/v1/connectors/",
            "/api/v1/auth/",
        )
    ):
        return JSONResponse({"detail": _explain(exc)}, status_code=422)
    return await request_validation_exception_handler(request, exc)


def create_api(deps: ApiDeps) -> FastAPI:
    app = FastAPI(
        title="Open-TI API", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.deps = deps
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.middleware("http")(_security)
    for router in ROUTERS:
        app.include_router(router, prefix="/api/v1")
    _mount_web(app, deps.web_dist)
    return app


def openapi_schema(deps: ApiDeps) -> dict[str, Any]:
    """供前端生成类型（Task 8）；不经 HTTP 暴露。"""
    return create_api(deps).openapi()
