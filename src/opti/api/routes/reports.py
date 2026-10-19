"""日报、周报与月报（设计文档 13、14）：列表、详情（JSON 内容）与 HTML 下载。"""

from __future__ import annotations

from typing import Annotated, cast
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select

from opti.api.deps import Principal, get_deps, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.api.schemas import ReportKind, ReportOut, ReportPage, ReportSummary
from opti.core.reports import KINDS, month_label, report_view, title
from opti.db.models import Report

router = APIRouter(tags=["reports"])
Reader = Annotated[Principal, Depends(require(Perm.REPORTS_READ))]


def _summary(r: Report) -> ReportSummary:
    raw = r.content.get("totals")
    totals = (
        {str(k): v for k, v in raw.items() if isinstance(v, int)} if isinstance(raw, dict) else {}
    )
    return ReportSummary(
        id=r.id, kind=cast(ReportKind, r.kind if r.kind in KINDS else "daily"), title=title(r.content),
        period_start=r.period_start, period_end=r.period_end, created_at=r.created_at, sent_at=r.sent_at,
        totals=totals,
    )  # fmt: skip


async def _get(request: Request, report_id: int) -> Report:
    deps = get_deps(request)
    async with deps.sessions() as s:
        row = await s.get(Report, report_id)
    if row is None or row.project_id != deps.rules.project:
        raise HTTPException(404, "report not found")
    return row


@router.get("/reports")
async def list_reports(
    request: Request,
    user: Reader,
    kind: ReportKind | None = None,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
) -> ReportPage:
    deps = get_deps(request)
    q = select(Report).where(Report.project_id == deps.rules.project)
    if kind is not None:
        q = q.where(Report.kind == kind)
    count_stmt = q
    if cursor is not None:
        q = q.where(Report.id < cursor)
    async with deps.sessions() as s:
        total = await page_total(s, count_stmt, page, cursor)
        rows = (
            await s.scalars(
                q.order_by(Report.id.desc()).offset(page_offset(page, limit)).limit(limit + 1)
            )
        ).all()
    items = [_summary(r) for r in rows[:limit]]
    return ReportPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit and items else None
    )


@router.get("/reports/{report_id}")
async def get_report(request: Request, user: Reader, report_id: int) -> ReportOut:
    row = await _get(request, report_id)
    return ReportOut(**_summary(row).model_dump(), content=row.content)


@router.get("/reports/{report_id}/html", include_in_schema=False)
async def download_report(request: Request, user: Reader, report_id: int) -> Response:
    row = await _get(request, report_id)
    view = report_view(row.id, row.content, get_deps(request).public_base_url)
    tz = ZoneInfo(str(row.content.get("timezone") or "UTC"))
    stamp = (
        month_label(row.period_start, tz) if row.kind == "monthly" else f"{row.period_end:%Y%m%d}"
    )
    headers = {
        "Content-Disposition": f'attachment; filename="report-{row.kind}-{stamp}.html"',
        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
        "Cache-Control": "private, no-store",
    }
    return Response(view.html, media_type="text/html; charset=utf-8", headers=headers)
