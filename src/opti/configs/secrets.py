"""Web 配置密钥（设计 2026-10-12-web-config-phase2-alerting）：加密存库、只写不读、环境变量兜底。"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.secretbox import Keyring, SecretError
from opti.db.models import ConfigSecret

NO_KEY = "服务器未配置主密钥 OPTI_ENCRYPTION_KEY"


class SecretWriteError(Exception):
    pass


@dataclass(frozen=True)
class Resolved:
    values: dict[str, str | None]
    problems: dict[str, str]


@dataclass(frozen=True)
class SecretState:
    name: str
    set: bool
    hint: str | None
    source: Literal["db", "env", "none"]
    updated_by: str | None
    updated_at: datetime | None


def aad(kind: str, name: str) -> str:
    return f"config_secret:{kind}:{name}"


def _hint(value: str) -> str | None:
    return value[-4:] if len(value) >= 12 else None  # 太短的密钥不显示末尾，避免泄露大半


async def _rows(s: AsyncSession, kind: str) -> dict[str, ConfigSecret]:
    rows = await s.scalars(select(ConfigSecret).where(ConfigSecret.kind == kind))
    return {r.name: r for r in rows}


def _env_value(name: str, fallback: Mapping[str, str], env: Mapping[str, str]) -> str | None:
    var = fallback.get(name)
    return (env.get(var) or None) if var else None


def resolve_env(
    names: Iterable[str], *, fallback: Mapping[str, str], env: Mapping[str, str] = os.environ
) -> Resolved:
    return Resolved({n: _env_value(n, fallback, env) for n in names}, {})


async def resolve(
    s: AsyncSession,
    kind: str,
    names: Iterable[str],
    keyring: Keyring | None,
    *,
    fallback: Mapping[str, str],
    env: Mapping[str, str] = os.environ,
    stored_only: bool = False,
) -> Resolved:
    """stored_only：只返回库中有记录的名字（含显式清除），环境变量兜底交给读取方。"""
    stored = await _rows(s, kind)
    values: dict[str, str | None] = {}
    problems: dict[str, str] = {}
    for name in names:
        row = stored.get(name)
        if row is None:
            if stored_only:
                continue
            values[name] = _env_value(name, fallback, env)
        elif row.value_enc is None:
            values[name] = None
        elif keyring is None:
            values[name], problems[name] = None, NO_KEY
        else:
            try:
                values[name] = keyring.decrypt(row.value_enc, aad=aad(kind, name))
            except SecretError as e:
                values[name], problems[name] = None, f"{name} 无法解密：{e}"
    return Resolved(values, problems)


async def write(
    s: AsyncSession,
    kind: str,
    changes: Mapping[str, str | None],
    *,
    keyring: Keyring | None,
    user: str,
    now: datetime,
) -> None:
    """changes：键名 → 新值（替换）或 None（清除并屏蔽环境变量）。"""
    if keyring is None and any(v is not None for v in changes.values()):
        raise SecretWriteError(NO_KEY)
    for name, value in changes.items():
        enc = None if value is None else keyring.encrypt(value, aad=aad(kind, name))  # type: ignore[union-attr]
        values = {
            "value_enc": enc,
            "hint": None if value is None else _hint(value),
            "updated_by": user,
            "updated_at": now,
        }
        await s.execute(
            pg_insert(ConfigSecret)
            .values(kind=kind, name=name, **values)
            .on_conflict_do_update(index_elements=["kind", "name"], set_=values)
        )


async def prune(
    s: AsyncSession, kind: str, keep: set[str], *, prefix: str = "channel:"
) -> list[str]:
    stored = await _rows(s, kind)
    gone = sorted(n for n in stored if n.startswith(prefix) and n not in keep)
    if gone:
        await s.execute(
            delete(ConfigSecret).where(ConfigSecret.kind == kind, ConfigSecret.name.in_(gone))
        )
    return gone


async def states(
    s: AsyncSession,
    kind: str,
    names: Iterable[str],
    *,
    fallback: Mapping[str, str],
    env: Mapping[str, str] = os.environ,
) -> list[SecretState]:
    stored = await _rows(s, kind)
    out: list[SecretState] = []
    for name in sorted(names):
        row = stored.get(name)
        if row is not None:
            has = row.value_enc is not None
            out.append(
                SecretState(
                    name, has, row.hint, "db" if has else "none", row.updated_by, row.updated_at
                )
            )
        elif _env_value(name, fallback, env):
            out.append(SecretState(name, True, None, "env", None, None))
        else:
            out.append(SecretState(name, False, None, "none", None, None))
    return out


async def stamp(s: AsyncSession, kind: str) -> str:
    """密钥变更戳：任何写入、清除、删除都会改变它；不暴露密钥内容。"""
    h = hashlib.sha256()
    for row in sorted((await _rows(s, kind)).values(), key=lambda r: r.name):
        h.update(row.name.encode())
        h.update(row.updated_at.isoformat().encode())
        h.update(hashlib.sha256(row.value_enc or b"").digest())
    return h.hexdigest()


async def rekey(s: AsyncSession, keyring: Keyring) -> int:
    changed = 0
    for row in (await s.scalars(select(ConfigSecret).with_for_update())).all():
        if row.value_enc is None or keyring.is_current(row.value_enc):
            continue
        plain = keyring.decrypt(row.value_enc, aad=aad(row.kind, row.name))
        row.value_enc = keyring.encrypt(plain, aad=aad(row.kind, row.name))
        changed += 1
    return changed
