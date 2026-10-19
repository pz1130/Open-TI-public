"""机器对机器的 API Token（设计文档 15、16.3）：命令行签发；库中只存 SHA-256；带作用域与到期时间。"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Sequence
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import ApiToken

TOKEN_PREFIX = "opti_"
SCOPES = frozenset({"blocklist:export", "stix:export"})
MAX_DAYS = 730
_NAME = re.compile(r"^[a-z0-9._-]{2,64}$")


class TokenError(ValueError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_token(
    session: AsyncSession, *, name: str, scopes: Sequence[str], days: int, actor: str, now: datetime
) -> tuple[ApiToken, str]:
    if not _NAME.fullmatch(name):
        raise TokenError("名称只能包含小写字母、数字、点、下划线和连字符（2–64 个字符）")
    unknown = sorted(set(scopes) - SCOPES)
    if unknown or not scopes:
        raise TokenError(
            f"未知或缺少作用域：{', '.join(unknown) or '（空）'}；可用：{', '.join(sorted(SCOPES))}"
        )
    if not 1 <= days <= MAX_DAYS:
        raise TokenError(f"有效期必须在 1–{MAX_DAYS} 天之间")
    if await session.scalar(select(ApiToken.id).where(ApiToken.name == name)) is not None:
        raise TokenError(f"令牌 {name} 已存在")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(
        name=name, token_hash=_hash(token), prefix=token[:12], scopes=sorted(set(scopes)),
        created_by=actor, created_at=now, expires_at=now + timedelta(days=days),
    )  # fmt: skip
    session.add(row)
    await session.flush()
    return row, token


async def revoke_token(session: AsyncSession, name: str, now: datetime) -> ApiToken:
    row = await session.scalar(
        select(ApiToken)
        .where(ApiToken.name == name, ApiToken.revoked_at.is_(None))
        .with_for_update()
    )
    if row is None:
        raise TokenError(f"令牌 {name} 不存在或已吊销")
    row.revoked_at = now
    return row


async def list_tokens(session: AsyncSession) -> list[ApiToken]:
    return list((await session.scalars(select(ApiToken).order_by(ApiToken.id))).all())


async def resolve_token(
    session: AsyncSession, token: str, scope: str, now: datetime
) -> ApiToken | None:
    if not token.startswith(TOKEN_PREFIX) or len(token) > 200:
        return None
    row = await session.scalar(
        select(ApiToken).where(ApiToken.token_hash == _hash(token)).with_for_update()
    )
    if (
        row is None
        or row.revoked_at is not None
        or row.expires_at <= now
        or scope not in row.scopes
    ):
        return None
    row.last_used_at = now
    return row
