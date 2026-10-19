"""审计日志（设计文档 16.3）：只追加；每条记录的哈希覆盖前一条哈希与本条全部字段，任何改动都会断链。"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import AuditLog

GENESIS = "0" * 64
AUDIT_LOCK_KEY = 7_310_016  # pg_advisory_xact_lock 的键：串行追加，保证链不分叉


def _digest(
    prev_hash: str,
    ts: datetime,
    actor: str,
    action: str,
    target_type: str | None,
    target_id: str | None,
    detail: Mapping[str, Any],
    ip: str | None,
    request_id: str | None,
) -> str:
    payload = {
        "prev": prev_hash,
        "ts": ts.astimezone(UTC).isoformat(),
        "actor": actor,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "detail": detail,
        "ip": ip,
        "request_id": request_id,
    }
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


async def append(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    now: datetime,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: Mapping[str, Any] | None = None,
    ip: str | None = None,
    request_id: str | None = None,
) -> AuditLog:
    await session.execute(select(func.pg_advisory_xact_lock(AUDIT_LOCK_KEY)))
    prev = await session.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1))
    prev_hash = prev or GENESIS
    ts = now.astimezone(UTC)
    body = dict(detail or {})
    row = AuditLog(
        ts=ts,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=body,
        ip=ip,
        request_id=request_id,
        prev_hash=prev_hash,
        hash=_digest(prev_hash, ts, actor, action, target_type, target_id, body, ip, request_id),
    )
    session.add(row)
    await session.flush()
    return row


async def verify_chain(session: AsyncSession, *, batch: int = 1000) -> int | None:
    prev = GENESIS
    last_id = 0
    while True:
        rows = (
            await session.scalars(
                select(AuditLog).where(AuditLog.id > last_id).order_by(AuditLog.id).limit(batch)
            )
        ).all()
        if not rows:
            return None
        for r in rows:
            expected = _digest(
                r.prev_hash, r.ts, r.actor, r.action, r.target_type, r.target_id,
                r.detail, r.ip, r.request_id,
            )  # fmt: skip
            if r.prev_hash != prev or r.hash != expected:
                return r.id
            prev, last_id = r.hash, r.id
