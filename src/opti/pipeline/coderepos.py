"""Schedule related public repositories for secret scanning."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.db.models import CodeRepo

CODE_ENRICHERS = ("secret_scan",)


async def touch(session: AsyncSession, project_id: str, repo: str, now: datetime) -> None:
    stmt = pg_insert(CodeRepo).values(
        project_id=project_id,
        repo=repo,
        first_seen=now,
        last_hit_at=now,
        scan_status="pending",
        next_scan_at=now,
    )
    await session.execute(
        stmt.on_conflict_do_update(
            constraint="uq_code_repo_project_id",
            set_={"last_hit_at": now, "next_scan_at": func.least(CodeRepo.next_scan_at, now)},
        )
    )


async def due(
    session: AsyncSession, now: datetime, *, limit: int, project_id: str
) -> list[CodeRepo]:
    stmt = (
        select(CodeRepo)
        .where(CodeRepo.project_id == project_id, CodeRepo.next_scan_at <= now)
        .order_by(CodeRepo.next_scan_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return list((await session.scalars(stmt)).all())


def record_scan(row: CodeRepo, data: dict[str, Any], now: datetime) -> None:
    if data.get("scanned"):
        row.scan_status = "ok"
        row.last_commit = str(data.get("commit") or "")[:40] or None
        row.last_scanned_at, row.next_scan_at = (
            now,
            now + timedelta(days=policy.current().scanning.repo_rescan_days),
        )
    elif data.get("skipped"):
        row.scan_status = f"skipped:{data['skipped']}"[:100]
        row.last_scanned_at, row.next_scan_at = (
            now,
            now + timedelta(days=policy.current().scanning.repo_rescan_days),
        )
    else:
        row.scan_status = f"error:{data.get('error') or 'unknown'}"[:100]
        row.next_scan_at = now + timedelta(hours=policy.current().scanning.repo_retry_hours)
