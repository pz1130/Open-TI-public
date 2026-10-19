"""审计日志查看与完整性校验（设计文档 16.3，需要 audit:read）。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select

from opti.api.deps import Principal, get_deps, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.api.schemas import AuditEntry, AuditPage, AuditVerifyOut
from opti.db import audit
from opti.db.models import AuditLog

router = APIRouter(tags=["audit"])
Auditor = Annotated[Principal, Depends(require(Perm.AUDIT_READ))]


@router.get("/audit-logs")
async def list_logs(
    request: Request,
    user: Auditor,
    action: Annotated[str | None, Query(max_length=100)] = None,
    actor: Annotated[str | None, Query(max_length=100)] = None,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AuditPage:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    count_stmt = stmt
    if cursor is not None:
        stmt = stmt.where(AuditLog.id < cursor)
    async with get_deps(request).sessions() as s:
        total = await page_total(s, count_stmt, page, cursor)
        rows = (
            await s.scalars(
                stmt.order_by(AuditLog.id.desc()).offset(page_offset(page, limit)).limit(limit + 1)
            )
        ).all()
    items = [
        AuditEntry(
            id=r.id,
            ts=r.ts,
            actor=r.actor,
            action=r.action,
            target_type=r.target_type,
            target_id=r.target_id,
            detail=dict(r.detail),
            ip=r.ip,
            request_id=r.request_id,
        )
        for r in rows[:limit]
    ]
    return AuditPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit and items else None
    )


@router.get("/audit-logs/verify")
async def verify(request: Request, user: Auditor) -> AuditVerifyOut:
    deps = get_deps(request)
    async with deps.sessions() as s:
        broken = await audit.verify_chain(s)
    return AuditVerifyOut(ok=broken is None, first_broken_id=broken, checked_at=deps.clock())
