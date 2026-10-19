"""工单推送与回写（设计文档 12、D8）：每个告警最多推送一次；回调按签名时间单调递增，拒绝重放。"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.views import load_views
from opti.core import policy
from opti.db.models import Alert
from opti.tickets.client import PushResult, TicketClient
from opti.tickets.config import TicketsConfig


class TicketError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


async def push(
    session: AsyncSession, client: TicketClient, alert: Alert, *, base_url: str, now: datetime
) -> PushResult:
    if isinstance(alert.routing, dict) and alert.routing.get("category") == "credential_exposure":
        raise TicketError(409, "use the exposure push endpoint for credential exposure")
    if alert.ticket_pushed_at is not None:
        raise TicketError(409, "alert already pushed to the ticket system")
    if alert.status == "superseded":
        raise TicketError(409, "alert superseded by a newer alert")
    views = await load_views(session, [alert.id], base_url)
    if not views:
        raise TicketError(404, "alert not found")
    result = await client.push(views[0])  # 失败时抛出，不盖章，可重试
    alert.ticket_pushed_at = now
    if result.ref and alert.ticket_ref is None:
        alert.ticket_ref = result.ref
    return result


async def next_auto_push(
    session: AsyncSession, cfg: TicketsConfig, now: datetime, *, exclude: Sequence[int]
) -> Alert | None:
    if not cfg.auto_push:
        return None
    stmt = select(Alert).where(
        Alert.status.in_(("open", "acknowledged")),
        Alert.ticket_pushed_at.is_(None),
        Alert.ignored_at.is_(None),
        Alert.ticket_ref.is_(None),
        Alert.severity.in_([s.value for s in cfg.auto_push]),
        Alert.created_at > now - timedelta(hours=policy.current().delivery.ticket_window_hours),
        func.coalesce(Alert.routing["category"].astext, "") != "credential_exposure",
    )
    if exclude:
        stmt = stmt.where(Alert.id.not_in(list(exclude)))
    return await session.scalar(stmt.order_by(Alert.id).limit(1).with_for_update(skip_locked=True))


async def apply_callback(
    session: AsyncSession,
    cfg: TicketsConfig,
    alert: Alert,
    *,
    ref: str | None,
    status: str | None,
    signed_at: datetime,
    now: datetime,
) -> dict[str, Any]:
    """同一告警的回调签名时间必须严格递增（秒级）：重放或乱序的旧回调返回 409。"""
    if alert.ticket_synced_at is not None and signed_at <= alert.ticket_synced_at:
        raise TicketError(409, "stale or replayed callback")
    if ref is not None and alert.ticket_ref not in (None, ref):
        raise TicketError(409, "alert is linked to a different ticket")
    before = {
        "ticket_ref": alert.ticket_ref,
        "ticket_status": alert.ticket_status,
        "status": alert.status,
    }
    if ref is not None:
        alert.ticket_ref = ref
        alert.ticket_pushed_at = alert.ticket_pushed_at or now
    if status is not None:
        alert.ticket_status = status
        mapped = cfg.status_map.get(status)
        if mapped is not None and alert.status != "superseded" and mapped != alert.status:
            alert.status = mapped
            alert.closed_at = now if mapped == "closed" else None
    alert.ticket_synced_at = signed_at
    alert.updated_at = now
    after = {
        "ticket_ref": alert.ticket_ref,
        "ticket_status": alert.ticket_status,
        "status": alert.status,
    }
    return {"before": before, "after": after}
