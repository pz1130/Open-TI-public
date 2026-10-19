"""接口公共依赖：当前用户、权限检查、审计记录。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, cast

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti.alerting.email import SendFn, smtp_sender
from opti.alerting.runtime import ConfigBoundTickets
from opti.api.access import effective_permissions, roles_for
from opti.api.oidc.client import OidcClient
from opti.api.oidc.runtime import ConfigBoundOidc
from opti.api.rbac import Perm
from opti.api.security import resolve_session
from opti.api.throttle import SlidingWindow
from opti.configs.identity import IdentityConfig
from opti.configs.runtime import ConfigRuntime, ConfigSnapshot, KeyValue
from opti.core.config import ProjectRules
from opti.core.secretbox import Keyring
from opti.db import audit
from opti.organization import Organization
from opti.pipeline.enrichment import utcnow
from opti.sdk.registry import Registry
from opti.settings import Settings
from opti.sharing import SharingConfig
from opti.storage.objects import ObjectStore
from opti.takedown.config import TakedownConfig
from opti.tickets.client import MIN_KEY_LENGTH, TicketClient
from opti.tickets.config import TicketsConfig
from opti.translation import Translator

COOKIE = "opti_session"
_request_snapshot: ContextVar[ConfigSnapshot | None] = ContextVar(
    "opti_request_config_snapshot", default=None
)


def pin_request_snapshot(snapshot: ConfigSnapshot) -> Token[ConfigSnapshot | None]:
    return _request_snapshot.set(snapshot)


def reset_request_snapshot(token: Token[ConfigSnapshot | None]) -> None:
    _request_snapshot.reset(token)


@dataclass
class ApiDeps:
    settings: Settings
    config: ConfigRuntime
    sessions: async_sessionmaker[AsyncSession]
    store: ObjectStore | None
    registry: Registry = field(default_factory=Registry)
    clock: Callable[[], datetime] = field(default=utcnow)
    web_dist: Path | None = None
    ticket_source: ConfigBoundTickets | None = None
    _tickets_override: TicketClient | None = field(default=None, repr=False)
    keyring: Keyring | None = None
    llm_transport: httpx.AsyncBaseTransport | None = None
    oidc: OidcClient | None = None
    oidc_source: ConfigBoundOidc | None = None
    translator: Translator | None = None
    translation_requests: SlidingWindow = field(
        default_factory=lambda: SlidingWindow(10, timedelta(minutes=1))
    )
    login_failures: SlidingWindow = field(
        default_factory=lambda: SlidingWindow(20, timedelta(minutes=15))
    )
    oidc_starts: SlidingWindow = field(
        default_factory=lambda: SlidingWindow(30, timedelta(minutes=1))
    )
    edge_store: KeyValue | None = None  # Valkey：边缘服务生效状态
    alerting_transport: httpx.AsyncBaseTransport | None = None  # 测试注入
    smtp_sender: Callable[..., SendFn] = field(default=smtp_sender)
    alerting_tests: SlidingWindow = field(
        default_factory=lambda: SlidingWindow(5, timedelta(minutes=1))
    )

    @property
    def identity(self) -> IdentityConfig:
        snapshot = _request_snapshot.get() or self.config.snapshot
        if self.config.settings is None and snapshot.version("identity") == 0:
            # 测试与无数据库的固定依赖继续沿用注入的启动参数。
            return IdentityConfig.model_construct(
                local_login=self.settings.local_login,
                session_hours=self.settings.session_hours,
                cookie_secure=self.settings.cookie_secure,
            )
        return snapshot.identity

    @property
    def snapshot(self) -> ConfigSnapshot:
        return _request_snapshot.get() or self.config.snapshot

    @property
    def rules(self) -> ProjectRules:
        snapshot = _request_snapshot.get()
        return (snapshot or self.config.snapshot).rules

    @property
    def organization(self) -> Organization:
        snapshot = _request_snapshot.get()
        return (snapshot or self.config.snapshot).organization

    @property
    def takedown(self) -> TakedownConfig:
        snapshot = _request_snapshot.get()
        return (snapshot or self.config.snapshot).takedown

    @property
    def sharing(self) -> SharingConfig:
        snapshot = _request_snapshot.get()
        return (snapshot or self.config.snapshot).sharing

    @property
    def tickets(self) -> TicketClient | None:
        if self._tickets_override is not None:
            return self._tickets_override
        return self.ticket_source.current() if self.ticket_source is not None else None

    @tickets.setter
    def tickets(self, client: TicketClient | None) -> None:
        self._tickets_override = client

    @property
    def tickets_cfg(self) -> TicketsConfig:
        snapshot = _request_snapshot.get()
        return (snapshot or self.config.snapshot).tickets

    @property
    def tickets_key(self) -> bytes | None:
        snapshot = _request_snapshot.get()
        key = (snapshot or self.config.snapshot).secrets("tickets").get("signing_key")
        return key.encode() if key and len(key) >= MIN_KEY_LENGTH else None

    @property
    def public_base_url(self) -> str:
        return self.config.snapshot.alerting.public_base_url


def get_deps(request: Request) -> ApiDeps:
    deps = cast(ApiDeps, request.app.state.deps)
    if deps.oidc_source is not None:
        deps.oidc = deps.oidc_source.current()
    if deps.keyring is None:
        # 其他 API 副本初始化后，当前副本也立即可保存凭据。
        ring = Keyring.from_env(state_dir=deps.settings.state_dir)
        if ring is not None:
            deps.keyring = ring
            deps.config.set_keyring(ring)
    return deps


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    display_name: str
    roles: tuple[str, ...]
    perms: frozenset[Perm]
    auth_source: str = "local"
    must_change_password: bool = False


async def current_user(request: Request) -> Principal:
    deps = get_deps(request)
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "not authenticated")
    async with deps.sessions.begin() as s:
        user = await resolve_session(s, token, deps.clock())
        if user is None:
            raise HTTPException(401, "session expired")
        if user.must_change_password and request.url.path not in {
            "/api/v1/auth/me",
            "/api/v1/auth/logout",
            "/api/v1/auth/password",
        }:
            raise HTTPException(
                403, {"reason": "password_change_required", "message": "请先修改初始密码"}
            )
        expected_project = request.headers.get("X-Opti-Project")
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and expected_project is not None
            and expected_project != deps.rules.project
        ):
            raise HTTPException(
                409,
                {"reason": "project_changed", "message": "全平台项目已切换，请刷新页面后重试"},
            )
        return Principal(
            user.id,
            user.username,
            user.display_name,
            tuple(roles_for(user)),
            await effective_permissions(s, user),
            user.auth_source,
            user.must_change_password,
        )


CurrentUser = Annotated[Principal, Depends(current_user)]


def require(perm: Perm) -> Callable[[Principal], Awaitable[Principal]]:
    async def check(user: CurrentUser) -> Principal:
        if perm not in user.perms:
            raise HTTPException(403, "forbidden")
        return user

    return check


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def record(
    session: AsyncSession,
    request: Request,
    actor: Principal | str,
    action: str,
    *,
    target_type: str | None = None,
    target_id: object | None = None,
    detail: Mapping[str, Any] | None = None,
) -> None:
    await audit.append(
        session,
        actor=actor.username if isinstance(actor, Principal) else actor,
        action=action,
        now=get_deps(request).clock(),
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        detail=detail,
        ip=client_ip(request),
        request_id=getattr(request.state, "request_id", None),
    )
