"""单点登录状态与账号（设计文档 15、16）：一次性登录状态、站内跳转校验、首次登录建档、每次登录同步角色。"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.oidc.client import Identity, OidcError, pkce_pair
from opti.api.oidc.config import OidcConfig
from opti.db.models import AppUser, OidcLogin

LOGIN_TTL = timedelta(minutes=10)
NEXT_MAX = 512


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def safe_next(value: str | None) -> str:
    """登录后只跳回站内页面：拒绝绝对地址、协议相对地址、反斜杠、控制字符与接口路径（防开放重定向）。"""
    v = value or ""
    if (
        not v.startswith("/")
        or v.startswith("//")
        or v.startswith("/api/")
        or len(v) > NEXT_MAX
        or "\\" in v
        or any(ord(c) < 32 or ord(c) == 127 for c in v)
    ):
        return "/"
    return v


@dataclass(frozen=True)
class Started:
    state: str
    nonce: str
    challenge: str
    binding: str  # 写入浏览器绑定 Cookie


@dataclass(frozen=True)
class Pending:
    nonce: str
    code_verifier: str
    next_path: str


async def begin(session: AsyncSession, *, now: datetime, next_path: str | None) -> Started:
    await session.execute(delete(OidcLogin).where(OidcLogin.expires_at <= now))  # 顺手清理过期状态
    state, nonce, binding = (
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
    )
    verifier, challenge = pkce_pair()
    session.add(
        OidcLogin(
            id=_h(state), binding_hash=_h(binding), nonce=nonce, code_verifier=verifier,
            next_path=safe_next(next_path), created_at=now, expires_at=now + LOGIN_TTL,
        )
    )  # fmt: skip
    await session.flush()
    return Started(state, nonce, challenge, binding)


async def finish(
    session: AsyncSession, *, state: str, binding: str | None, now: datetime
) -> Pending | None:
    """一次性：找到即删除（调用方提交事务），再判断是否过期、是否由同一浏览器发起。"""
    if not state:
        return None
    row = await session.scalar(select(OidcLogin).where(OidcLogin.id == _h(state)).with_for_update())
    if row is None:
        return None
    await session.delete(row)
    if (
        row.expires_at <= now
        or not binding
        or not hmac.compare_digest(row.binding_hash, _h(binding))
    ):
        return None
    return Pending(row.nonce, row.code_verifier, row.next_path)


async def upsert_user(
    session: AsyncSession, cfg: OidcConfig, ident: Identity, now: datetime
) -> tuple[AppUser, dict[str, Any]]:
    roles = cfg.roles_for(ident.claim_values)
    user = await session.scalar(
        select(AppUser)
        .where(AppUser.oidc_issuer == ident.issuer, AppUser.oidc_subject == ident.subject)
        .with_for_update()
    )
    if user is None:
        # 不按用户名合并：身份提供方中同名的用户不能接管本地（应急）账号
        if (
            await session.scalar(select(AppUser.id).where(AppUser.username == ident.username))
            is not None
        ):
            raise OidcError(
                "username_conflict", f"username {ident.username} belongs to another account"
            )
        if not roles:
            raise OidcError("no_role", "no platform role is mapped to this user")
        user = AppUser(
            username=ident.username, display_name=ident.display_name, password_hash="!", roles=roles,
            active=True, failed_logins=0, auth_source="oidc", oidc_issuer=ident.issuer,
            oidc_subject=ident.subject, email=ident.email, created_at=now, last_login_at=now,
        )  # fmt: skip
        session.add(user)
        await session.flush()
        return user, {"created": True, "roles": roles}
    if not user.active:
        raise OidcError("disabled", "account is disabled on the platform")
    if not roles:
        raise OidcError("no_role", "no platform role is mapped to this user")
    before = sorted(user.roles)
    user.roles = roles
    user.display_name = ident.display_name or user.display_name
    user.email = ident.email
    user.last_login_at = now
    user.access_version += 1
    return user, {"roles_before": before, "roles": roles}
