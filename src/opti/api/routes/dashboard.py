"""总览仪表盘（设计文档 14）与可自定义布局。"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy import delete, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.deps import CurrentUser, Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import DashboardOut, DefaultLayoutOut, LayoutOut, LayoutSpec
from opti.db.models import DashboardLayout
from opti.pipeline import dashboard

router = APIRouter(tags=["dashboard"])
Reader = Annotated[Principal, Depends(require(Perm.ALERTS_READ))]
DefaultAdmin = Annotated[Principal, Depends(require(Perm.DASHBOARD_DEFAULT))]


@router.get("/dashboard")
async def get_dashboard(
    request: Request,
    user: Reader,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    category: Annotated[str | None, Query(max_length=50)] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = dashboard.TOP,
) -> DashboardOut:
    deps = get_deps(request)
    async with deps.sessions() as s:
        data = await dashboard.build(
            s, deps.rules, now=deps.clock(), days=days, category=category or None, limit=limit
        )
    return DashboardOut.model_validate(data)


def _parse(row: DashboardLayout | None) -> LayoutSpec | None:
    """库里的布局不再符合当前校验规则时当作不存在，回退到下一级。"""
    if row is None:
        return None
    try:
        return LayoutSpec.model_validate(row.layout)
    except ValidationError:
        return None


async def _upsert(
    s: AsyncSession, user_id: int | None, layout: LayoutSpec, actor: Principal, now: datetime
) -> None:
    values = {
        "user_id": user_id,
        "layout": layout.model_dump(mode="json"),
        "updated_at": now,
        "updated_by": actor.user_id,
    }
    stmt = insert(DashboardLayout).values(values)
    if user_id is None:
        stmt = stmt.on_conflict_do_update(
            # 对应迁移 0020 的表达式索引 uq_dashboard_layout_default
            index_elements=[text("(user_id IS NULL)")],
            index_where=DashboardLayout.user_id.is_(None),
            set_={"layout": stmt.excluded.layout, "updated_at": stmt.excluded.updated_at,
                  "updated_by": stmt.excluded.updated_by},
        )  # fmt: skip
    else:
        stmt = stmt.on_conflict_do_update(
            index_elements=[DashboardLayout.user_id],
            set_={"layout": stmt.excluded.layout, "updated_at": stmt.excluded.updated_at,
                  "updated_by": stmt.excluded.updated_by},
        )  # fmt: skip
    await s.execute(stmt)


@router.get("/dashboard/layout")
async def get_layout(request: Request, user: CurrentUser) -> LayoutOut:
    async with get_deps(request).sessions() as s:
        rows = {
            r.user_id: r
            for r in await s.scalars(
                select(DashboardLayout).where(
                    or_(DashboardLayout.user_id == user.user_id, DashboardLayout.user_id.is_(None))
                )
            )
        }
    sources: tuple[tuple[int | None, Literal["user", "default"]], ...] = (
        (user.user_id, "user"),
        (None, "default"),
    )
    for key, source in sources:
        if (layout := _parse(rows.get(key))) is not None:
            return LayoutOut(layout=layout, source=source)
    return LayoutOut(layout=None, source="builtin")


@router.put("/dashboard/layout")
async def put_layout(request: Request, user: CurrentUser, body: LayoutSpec) -> LayoutOut:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await _upsert(s, user.user_id, body, user, deps.clock())
    return LayoutOut(layout=body, source="user")


@router.delete("/dashboard/layout", status_code=204)
async def delete_layout(request: Request, user: CurrentUser) -> Response:
    async with get_deps(request).sessions.begin() as s:
        await s.execute(delete(DashboardLayout).where(DashboardLayout.user_id == user.user_id))
    return Response(status_code=204)


@router.get("/dashboard/layout/default")
async def get_default_layout(request: Request, user: DefaultAdmin) -> DefaultLayoutOut:
    async with get_deps(request).sessions() as s:
        row = await s.scalar(select(DashboardLayout).where(DashboardLayout.user_id.is_(None)))
    return DefaultLayoutOut(layout=_parse(row))


@router.put("/dashboard/layout/default")
async def put_default_layout(
    request: Request, user: DefaultAdmin, body: LayoutSpec
) -> DefaultLayoutOut:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await _upsert(s, None, body, user, deps.clock())
        await record(
            s, request, user, "dashboard.default.update", target_type="dashboard_layout",
            detail={"widgets": len(body.widgets), "types": sorted({w.type for w in body.widgets})},
        )  # fmt: skip
    return DefaultLayoutOut(layout=body)


@router.delete("/dashboard/layout/default", status_code=204)
async def delete_default_layout(request: Request, user: DefaultAdmin) -> Response:
    async with get_deps(request).sessions.begin() as s:
        await s.execute(delete(DashboardLayout).where(DashboardLayout.user_id.is_(None)))
        await record(s, request, user, "dashboard.default.clear", target_type="dashboard_layout")
    return Response(status_code=204)
