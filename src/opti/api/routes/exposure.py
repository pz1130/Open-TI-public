"""凭据暴露（设计文档 2.3、4.6）：泄露事件详情（只有数量）、受影响账户（受限、审计）、推给 IT。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.runtime import active_ticket_client
from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import ExposedAccountOut, ExposureOut, ExposurePushOut
from opti.db.models import Alert, AlertFinding, Finding
from opti.exposure import service as exposure_service
from opti.exposure.service import CATEGORY, PushError
from opti.sdk.http import HttpError
from opti.tickets.remote import TicketRemoteError

router = APIRouter(tags=["exposure"])
Reader = Annotated[Principal, Depends(require(Perm.ALERTS_READ))]
AccountReader = Annotated[Principal, Depends(require(Perm.EXPOSURE_ACCOUNTS))]
Pusher = Annotated[Principal, Depends(require(Perm.TICKETS_PUSH))]


async def _load(
    s: AsyncSession, alert_id: int, project: str, *, lock: bool = False
) -> tuple[Alert, Finding]:
    stmt = (
        select(Alert, Finding)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .where(Alert.id == alert_id, Alert.project_id == project)
    )
    if lock:
        stmt = stmt.with_for_update(of=Alert)
    row = (await s.execute(stmt)).first()
    if row is None or row[1].category != CATEGORY:
        raise HTTPException(404, "credential exposure alert not found")
    return row[0], row[1]


@router.get("/alerts/{alert_id}/exposure")
async def get_exposure(alert_id: int, request: Request, user: Reader) -> ExposureOut:
    deps = get_deps(request)
    async with deps.sessions() as s:
        _, finding = await _load(s, alert_id, deps.rules.project)
        total, pending = await exposure_service.counts(s, finding.id)
    ex = finding.match.get("exposure") or {}
    return ExposureOut(
        source=str(ex.get("source") or ""), kind=str(ex.get("kind") or "breach"), domain=str(ex.get("domain") or ""),
        title=str(ex.get("title") or ""), breach_date=ex.get("breach_date"), added_date=ex.get("added_date"),
        data_classes=[str(c) for c in ex.get("data_classes") or []], verified=bool(ex.get("verified", True)),
        fabricated=bool(ex.get("fabricated")), sensitive=bool(ex.get("sensitive")),
        spam_list=bool(ex.get("spam_list")), stealer_log=bool(ex.get("stealer_log")),
        affected=int(ex.get("affected") or 0), accounts_total=total, accounts_pending=pending,
        can_push=active_ticket_client(deps.tickets) is not None,
    )  # fmt: skip


@router.get("/alerts/{alert_id}/exposure/accounts")
async def exposure_accounts(
    alert_id: int, request: Request, user: AccountReader
) -> list[ExposedAccountOut]:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        _, finding = await _load(s, alert_id, deps.rules.project)
        rows = await exposure_service.accounts(s, finding.id)
        # 查看员工邮箱属于访问个人信息：只记数量，不记邮箱
        await record(s, request, user, "exposure.view_accounts", target_type="alert", target_id=alert_id,
                     detail={"count": len(rows)})  # fmt: skip
    return [
        ExposedAccountOut(
            email=r.email, first_seen=r.first_seen, last_seen=r.last_seen, pushed_at=r.pushed_at
        )
        for r in rows
    ]


@router.post("/alerts/{alert_id}/exposure/push")
async def push_exposure(alert_id: int, request: Request, user: Pusher) -> ExposurePushOut:
    deps = get_deps(request)
    client = active_ticket_client(deps.tickets)
    if client is None:
        raise HTTPException(503, "ticket integration is not configured")
    async with deps.sessions.begin() as s:
        alert, finding = await _load(s, alert_id, deps.rules.project, lock=True)
        try:
            count, result = await exposure_service.push(
                s, client, alert, finding, base_url=deps.public_base_url, now=deps.clock()
            )
        except PushError as e:
            raise HTTPException(e.status, e.message) from e
        except TicketRemoteError as e:  # 认证失败 / 被拒绝（含字段名）/ 不可用
            raise HTTPException(502, e.public_message()) from e
        except (HttpError, OSError) as e:
            raise HTTPException(502, f"ticket system unavailable: {type(e).__name__}") from e
        await record(s, request, user, "exposure.push", target_type="alert", target_id=alert_id,
                     detail={"count": count, "channel": result.channel, "ticket_ref": result.ref})  # fmt: skip
    return ExposurePushOut(pushed=count, channel=result.channel, ticket_ref=result.ref)
