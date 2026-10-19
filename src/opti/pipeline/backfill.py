"""关键词变动后的回溯（设计 2026-10-15-domain-keywords）：按需安排一次 crt.sh / dnstwist 运行。

每个连接器分别判断：不可运行 → unavailable；上一次仍在运行 → running；
距上次开始不足 manifest 的 min_interval_seconds → too_soon；否则排队 → queued。
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import ConnectorRun
from opti.gateway.records import ACTIVE_RUN
from opti.pipeline.domain_keywords import KeywordKind
from opti.sdk.registry import Registry

log = logging.getLogger(__name__)

BACKFILL_CONNECTORS = ("crtsh", "dnstwist")
# 哪类关键词变动需要哪个连接器回溯；合法第三方只影响判定，不需要回溯
TRIGGERS: dict[KeywordKind, tuple[str, ...]] = {
    "brand": ("crtsh", "dnstwist"),
    "restricted": ("crtsh",),
    "official": ("dnstwist",),
    "lookalike": (),
}
Status = Literal["queued", "running", "too_soon", "unavailable"]
Enqueue = Callable[[str], Awaitable[Any]]


@dataclass(frozen=True)
class BackfillResult:
    status: Status
    reason: str | None = None
    next_allowed_at: datetime | None = None
    run_id: int | None = None


async def request(
    session: AsyncSession,
    registry: Registry,
    connector_ids: Sequence[str],
    *,
    catalog: Mapping[str, Mapping[str, Any]],
    enqueue: Enqueue,
    now: datetime,
) -> dict[str, BackfillResult]:
    """catalog 为 pipeline.connectors.catalog() 的行（按 id），提供 runnable 与 reason。"""
    out: dict[str, BackfillResult] = {}
    for cid in connector_ids:
        row = catalog.get(cid)
        if row is None or row.get("runnable") is not True:
            reason = str(row.get("reason") or "") if row is not None else "unknown_connector"
            out[cid] = BackfillResult("unavailable", reason=reason)
            continue
        active = await session.scalar(
            select(ConnectorRun)
            .where(
                ConnectorRun.connector_id == cid,
                ConnectorRun.status.in_(ACTIVE_RUN),
            )
            .order_by(ConnectorRun.started_at.desc(), ConnectorRun.id.desc())
            .limit(1)
        )
        if active is not None:
            out[cid] = BackfillResult("running", run_id=active.id)
            continue
        last = await session.scalar(
            select(ConnectorRun)
            .where(ConnectorRun.connector_id == cid)
            .order_by(ConnectorRun.started_at.desc(), ConnectorRun.id.desc())
            .limit(1)
        )
        gap = timedelta(seconds=registry.manifest(cid).schedule.min_interval_seconds)
        if last is not None and now - last.started_at < gap:
            out[cid] = BackfillResult("too_soon", next_allowed_at=last.started_at + gap)
            continue
        try:
            await enqueue(cid)
        except Exception:
            log.exception("回溯排队失败：%s", cid)
            out[cid] = BackfillResult("unavailable", reason="queue_error")
            continue
        out[cid] = BackfillResult("queued")
    return out
