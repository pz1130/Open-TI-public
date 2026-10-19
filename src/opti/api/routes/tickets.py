"""工单推送、人工填写编号与工单系统回调（设计文档 12、15，D8）。"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.runtime import active_ticket_client
from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import TicketCallbackIn, TicketOut, TicketRefIn
from opti.db.models import Alert
from opti.sdk.http import HttpError
from opti.tickets import service as tickets_service
from opti.tickets.client import SIGNATURE_HEADER, TIMESTAMP_HEADER, SignatureError, verify
from opti.tickets.config import TicketsConfig
from opti.tickets.factory import ticket_url
from opti.tickets.remote import TicketRemoteError
from opti.tickets.service import TicketError

router = APIRouter(tags=["tickets"])
Pusher = Annotated[Principal, Depends(require(Perm.TICKETS_PUSH))]
MAX_CALLBACK_BYTES = 16 * 1024


async def _alert(s: AsyncSession, alert_id: int, project: str) -> Alert:
    alert = await s.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.project_id == project).with_for_update()
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    return alert


def _out(alert: Alert, available: bool, cfg: TicketsConfig) -> TicketOut:
    return TicketOut(
        ref=alert.ticket_ref, status=alert.ticket_status, pushed_at=alert.ticket_pushed_at,
        synced_at=alert.ticket_synced_at, available=available, url=ticket_url(cfg, alert.ticket_ref),
    )  # fmt: skip


@router.post("/alerts/{alert_id}/ticket")
async def push_ticket(alert_id: int, request: Request, user: Pusher) -> TicketOut:
    deps = get_deps(request)
    client = active_ticket_client(deps.tickets)
    if client is None:
        raise HTTPException(503, "ticket integration is not configured")
    async with deps.sessions.begin() as s:
        alert = await _alert(s, alert_id, deps.rules.project)
        try:
            result = await tickets_service.push(
                s, client, alert, base_url=deps.public_base_url, now=deps.clock()
            )
        except TicketError as e:
            raise HTTPException(e.status, e.message) from e
        except TicketRemoteError as e:  # 认证失败 / 被拒绝（含字段名）/ 不可用
            raise HTTPException(502, e.public_message()) from e
        except (HttpError, OSError) as e:  # OSError 覆盖 SMTP 失败
            raise HTTPException(502, f"ticket system unavailable: {type(e).__name__}") from e
        await record(
            s, request, user, "ticket.push", target_type="alert", target_id=alert.id,
            detail={"channel": result.channel, "ticket_ref": result.ref},
        )  # fmt: skip
        return _out(alert, True, deps.tickets_cfg)


@router.put("/alerts/{alert_id}/ticket")
async def set_ticket_ref(
    alert_id: int, body: TicketRefIn, request: Request, user: Pusher
) -> TicketOut:
    """工单系统不回调时由人工填写编号；填写后视为已推送，自动推送不再重复建单。"""
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions.begin() as s:
        alert = await _alert(s, alert_id, deps.rules.project)
        before = alert.ticket_ref
        alert.ticket_ref = body.ticket_ref
        alert.ticket_pushed_at = alert.ticket_pushed_at or now
        alert.updated_at = now
        await record(
            s, request, user, "ticket.set_ref", target_type="alert", target_id=alert.id,
            detail={"before": before, "after": body.ticket_ref},
        )  # fmt: skip
        return _out(alert, active_ticket_client(deps.tickets) is not None, deps.tickets_cfg)


@router.post("/integrations/tickets")
async def ticket_callback(request: Request) -> dict[str, bool]:
    """工单系统回调：不用 Cookie（豁免 X-Requested-With），以 HMAC 签名认证。"""
    deps = get_deps(request)
    if deps.tickets_key is None:
        raise HTTPException(503, "ticket callbacks are not configured")
    chunks = bytearray()
    async for chunk in request.stream():
        if len(chunks) + len(chunk) > MAX_CALLBACK_BYTES:
            raise HTTPException(413, "payload too large")
        chunks.extend(chunk)
    body = bytes(chunks)
    try:
        ts = verify(
            deps.tickets_key, request.headers.get(TIMESTAMP_HEADER), request.headers.get(SIGNATURE_HEADER),
            body, deps.clock(),
        )  # fmt: skip
    except SignatureError as e:
        raise HTTPException(401, "invalid signature") from e
    try:
        payload = TicketCallbackIn.model_validate_json(body)
    except ValidationError as e:
        raise HTTPException(422, "invalid callback payload") from e
    async with deps.sessions.begin() as s:
        alert = await _alert(s, payload.alert_id, deps.rules.project)
        try:
            change = await tickets_service.apply_callback(
                s, deps.tickets_cfg, alert, ref=payload.ticket_ref, status=payload.status,
                signed_at=datetime.fromtimestamp(ts, UTC), now=deps.clock(),
            )  # fmt: skip
        except TicketError as e:
            raise HTTPException(e.status, e.message) from e
        await record(
            s, request, "integration:tickets", "ticket.callback", target_type="alert",
            target_id=alert.id, detail=change,
        )  # fmt: skip
    return {"ok": True}
