"""config_revision（只追加）与 config_runtime_status 的读写。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.configs.kinds import digest_of
from opti.db.models import ConfigRevision, ConfigRuntimeStatus


@dataclass(frozen=True)
class Head:
    version: int
    digest: str


class VersionConflict(Exception):
    def __init__(self, current: int) -> None:
        super().__init__(f"配置已更新到 v{current}")
        self.current = current


async def heads(s: AsyncSession) -> dict[str, Head]:
    rows = await s.execute(
        select(ConfigRevision.kind, ConfigRevision.version, ConfigRevision.digest)
        .order_by(ConfigRevision.kind, ConfigRevision.version.desc())
        .ext(distinct_on(ConfigRevision.kind))
    )
    return {kind: Head(version, digest) for kind, version, digest in rows}


async def latest(s: AsyncSession, kind: str) -> ConfigRevision | None:
    return await s.scalar(
        select(ConfigRevision)
        .where(ConfigRevision.kind == kind)
        .order_by(ConfigRevision.version.desc())
        .limit(1)
    )


async def get(s: AsyncSession, kind: str, version: int) -> ConfigRevision | None:
    return await s.scalar(
        select(ConfigRevision).where(ConfigRevision.kind == kind, ConfigRevision.version == version)
    )


async def history(s: AsyncSession, kind: str) -> list[ConfigRevision]:
    rows = await s.scalars(
        select(ConfigRevision)
        .where(ConfigRevision.kind == kind)
        .order_by(ConfigRevision.version.desc())
    )
    return list(rows)


async def append(
    s: AsyncSession,
    kind: str,
    content: str,
    *,
    base_version: int,
    user: str,
    note: str | None,
    now: datetime,
    restored_from: int | None = None,
) -> ConfigRevision:
    # 同一 kind 的保存串行化：事务级咨询锁，提交或回滚时释放
    await s.execute(select(func.pg_advisory_xact_lock(func.hashtext(f"config_revision:{kind}"))))
    current = await latest(s, kind)
    version = current.version if current else 0
    if base_version != version:
        raise VersionConflict(version)
    row = ConfigRevision(
        kind=kind,
        version=version + 1,
        content=content,
        digest=digest_of(content),
        note=note,
        restored_from=restored_from,
        created_by=user,
        created_at=now,
    )
    s.add(row)
    await s.flush()
    return row


async def report_status(
    s: AsyncSession,
    *,
    process: str,
    kind: str,
    version: int,
    digest: str,
    error: str | None,
    now: datetime,
) -> None:
    values = {"version": version, "digest": digest, "error": error, "updated_at": now}
    await s.execute(
        pg_insert(ConfigRuntimeStatus)
        .values(process=process, kind=kind, **values)
        .on_conflict_do_update(index_elements=["process", "kind"], set_=values)
    )


async def statuses(s: AsyncSession) -> list[ConfigRuntimeStatus]:
    rows = await s.scalars(
        select(ConfigRuntimeStatus).order_by(ConfigRuntimeStatus.kind, ConfigRuntimeStatus.process)
    )
    return list(rows)
