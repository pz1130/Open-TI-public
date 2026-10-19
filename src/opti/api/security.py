"""本地账号与会话（S1，设计文档 16、19）：argon2id 口令、失败锁定、服务端会话（只存令牌哈希）。"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from collections.abc import Sequence
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.access import validate_assignments
from opti.db.models import ApiSession, AppUser

PASSWORD_MIN_LEN = 12
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
_USERNAME = re.compile(r"^[a-z0-9._-]{2,64}$")
_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("opti-timing-equalizer")


class UserError(ValueError):
    pass


def hash_password(password: str) -> str:
    if len(password) < PASSWORD_MIN_LEN:
        raise UserError(f"口令至少 {PASSWORD_MIN_LEN} 个字符")
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


async def _user(session: AsyncSession, username: str, *, lock: bool = False) -> AppUser | None:
    stmt = select(AppUser).where(AppUser.username == username)
    if lock:
        stmt = stmt.with_for_update()
    return (await session.scalars(stmt)).first()


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    roles: Sequence[str],
    now: datetime,
    display_name: str = "",
) -> AppUser:
    if not _USERNAME.fullmatch(username):
        raise UserError("用户名只能包含小写字母、数字、点、下划线和连字符（2–64 个字符）")
    try:
        await validate_assignments(session, roles, ())
    except ValueError as e:
        raise UserError(str(e)) from e
    if await _user(session, username) is not None:
        raise UserError(f"用户 {username} 已存在")
    user = AppUser(
        username=username,
        display_name=display_name,
        password_hash=await asyncio.to_thread(hash_password, password),
        roles=sorted(set(roles)),
        auth_source="local",
        created_at=now,
    )
    session.add(user)
    await session.flush()
    return user


async def set_password(session: AsyncSession, username: str, password: str) -> None:
    user = await _user(session, username, lock=True)
    if user is None:
        raise UserError(f"用户 {username} 不存在")
    if user.auth_source != "local":
        raise UserError(f"{username} 是单点登录账号，没有本地口令")
    user.password_hash = await asyncio.to_thread(hash_password, password)
    user.failed_logins, user.locked_until = 0, None
    user.must_change_password = False
    user.access_version += 1
    await session.execute(delete(ApiSession).where(ApiSession.user_id == user.id))


async def set_active(session: AsyncSession, username: str, active: bool) -> None:
    user = await _user(session, username, lock=True)
    if user is None:
        raise UserError(f"用户 {username} 不存在")
    user.active = active
    user.access_version += 1
    if not active:
        await session.execute(delete(ApiSession).where(ApiSession.user_id == user.id))


async def authenticate(
    session: AsyncSession, username: str, password: str, now: datetime
) -> AppUser | None:
    user = await _user(session, username, lock=True)
    if user is None or not user.active or user.auth_source != "local":
        await asyncio.to_thread(
            verify_password, _DUMMY_HASH, password
        )  # 耗时与真实用户一致，避免枚举用户名
        return None
    if user.locked_until is not None and user.locked_until > now:
        await asyncio.to_thread(verify_password, _DUMMY_HASH, password)
        return None
    if not await asyncio.to_thread(verify_password, user.password_hash, password):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until, user.failed_logins = now + LOCKOUT, 0
        return None
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
    return user


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(
    session: AsyncSession,
    user: AppUser,
    *,
    now: datetime,
    ttl: timedelta,
    ip: str | None,
    method: str = "password",
) -> str:
    token = secrets.token_urlsafe(32)
    session.add(
        ApiSession(
            id=_token_id(token),
            user_id=user.id,
            created_at=now,
            expires_at=now + ttl,
            last_seen_at=now,
            ip=ip,
            auth_method=method,
        )
    )
    await session.flush()
    return token


async def resolve_session(session: AsyncSession, token: str, now: datetime) -> AppUser | None:
    s = await session.get(ApiSession, _token_id(token))
    if s is None:
        return None
    if s.expires_at <= now:
        await session.delete(s)
        return None
    user = await session.get(AppUser, s.user_id)
    if user is None or not user.active:
        return None
    s.last_seen_at = now
    return user


async def end_session(session: AsyncSession, token: str) -> None:
    await session.execute(delete(ApiSession).where(ApiSession.id == _token_id(token)))


async def session_method(session: AsyncSession, token: str) -> str | None:
    s = await session.get(ApiSession, _token_id(token)) if token else None
    return s.auth_method if s is not None else None
