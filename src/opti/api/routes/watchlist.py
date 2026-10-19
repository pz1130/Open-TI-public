"""监视列表管理（设计文档 10.3、14）：查看状态与时间线、手动加入/编辑/移出。"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.deps import Principal, get_deps, record, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.api.schemas import (
    EvidenceOut,
    WatchCheckOut,
    WatchIn,
    WatchInspectionOut,
    WatchObservationOut,
    WatchOut,
    WatchPage,
)
from opti.core.domains import parse_domain
from opti.core.webpages import page_kind
from opti.db import repo
from opti.db.models import DomainObservation, Evidence, WatchedDomain
from opti.pipeline import watchlist
from opti.pipeline.tasks import recheck_watched_domain

router = APIRouter(tags=["watchlist"])
Reader = Annotated[Principal, Depends(require(Perm.WATCHLIST_READ))]
Writer = Annotated[Principal, Depends(require(Perm.WATCHLIST_WRITE))]


MANUAL_PREFIX = re.compile(r"^manual:[^:\s]+: ")


def _manual_reason(username: str, text: str) -> str:
    return f"manual:{username}: {text}"


def _edited_reason(current: str, submitted: str, username: str) -> str:
    """原因没改就原样保留（含自动生成的原因）；改了就记为编辑人写的，去掉编辑框里带回的旧前缀。"""
    if submitted == current:
        return current
    return _manual_reason(username, MANUAL_PREFIX.sub("", submitted, count=1))


def _out(w: WatchedDomain, inspection: WatchInspectionOut | None = None) -> WatchOut:
    return WatchOut(
        id=w.id,
        domain=w.domain,
        state=w.state,
        reason=w.reason,
        created_at=w.created_at,
        last_checked_at=w.last_checked_at,
        next_check_at=w.next_check_at,
        expires_at=w.expires_at,
        inspection=inspection,
    )


def _inspection(
    observation: DomainObservation, evidence: list[Evidence]
) -> WatchInspectionOut | None:
    page = observation.data.get("page") or observation.data.get("http_probe")
    if not isinstance(page, dict):
        return None
    status = observation.data.get("capture_status", "not_requested")
    return WatchInspectionOut(
        observed_at=observation.observed_at,
        verdict=page.get("verdict") or page_kind(page),
        source=str(page.get("source") or "probe"),
        title=str(page.get("title") or "")[:300],
        text_excerpt=str(page.get("text_excerpt") or "")[:1500],
        final_url=page.get("final_url") or page.get("url"),
        redirects=list(page.get("redirects") or [])[:20],
        status=page.get("status"),
        brand_terms=list(page.get("brand_terms") or [])[:30],
        has_password_field=bool(page.get("has_password_field")),
        capture_status=str(status),
        error=str(page["error"])[:300] if page.get("error") else None,
        evidence=[EvidenceOut.model_validate(ev, from_attributes=True) for ev in evidence],
    )


async def _evidence_for(
    session: AsyncSession, ids: list[int], user: Principal
) -> dict[int, list[Evidence]]:
    # 截图与 HTML 继续沿用证据权限，监视列表只读权限本身不授予下载权限。
    if Perm.EVIDENCE_READ not in user.perms or not ids:
        return {}
    rows = (
        await session.scalars(
            select(Evidence).where(Evidence.watch_observation_id.in_(ids)).order_by(Evidence.id)
        )
    ).all()
    grouped: dict[int, list[Evidence]] = {}
    for row in rows:
        if row.watch_observation_id is not None:
            grouped.setdefault(row.watch_observation_id, []).append(row)
    return grouped


@router.get("/watchlist")
async def list_watch(
    request: Request,
    user: Reader,
    state: Annotated[str | None, Query(max_length=20)] = None,
    include_expired: bool = False,
    q: Annotated[str | None, Query(max_length=253)] = None,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> WatchPage:
    deps = get_deps(request)
    stmt = select(WatchedDomain).where(WatchedDomain.project_id == deps.rules.project)
    if not include_expired:
        stmt = stmt.where(
            or_(WatchedDomain.expires_at.is_(None), WatchedDomain.expires_at > deps.clock()),
            WatchedDomain.paused_by_suppression.is_(False),
        )
    if state:
        stmt = stmt.where(WatchedDomain.state == state)
    if q:
        stmt = stmt.where(WatchedDomain.domain.contains(q.strip().lower(), autoescape=True))
    count_stmt = stmt
    if cursor is not None:
        stmt = stmt.where(WatchedDomain.id < cursor)
    async with deps.sessions() as s:
        total = await page_total(s, count_stmt, page, cursor)
        rows = (
            await s.scalars(
                stmt.order_by(WatchedDomain.id.desc())
                .offset(page_offset(page, limit))
                .limit(limit + 1)
            )
        ).all()
        latest = (
            select(
                DomainObservation.id,
                func.row_number()
                .over(
                    partition_by=DomainObservation.watched_domain_id,
                    order_by=(DomainObservation.observed_at.desc(), DomainObservation.id.desc()),
                )
                .label("ordinal"),
            )
            .where(DomainObservation.watched_domain_id.in_([w.id for w in rows[:limit]]))
            .subquery()
        )
        observed = (
            await s.scalars(
                select(DomainObservation)
                .join(latest, DomainObservation.id == latest.c.id)
                .where(latest.c.ordinal == 1)
            )
        ).all()
        evidence = await _evidence_for(s, [o.id for o in observed], user)
        inspections = {
            o.watched_domain_id: _inspection(o, evidence.get(o.id, [])) for o in observed
        }
    items = [_out(w, inspections.get(w.id)) for w in rows[:limit]]
    return WatchPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit and items else None
    )


@router.post("/watchlist", status_code=201)
async def add_watch(body: WatchIn, request: Request, user: Writer) -> WatchOut:
    parts = parse_domain(body.domain)
    if parts is None:
        raise HTTPException(422, "invalid domain")
    deps = get_deps(request)
    now = deps.clock()
    reason = _manual_reason(user.username, body.reason)
    async with deps.sessions.begin() as s:
        await repo.upsert_project(s, deps.rules)
        existing = await s.scalar(
            select(WatchedDomain)
            .where(
                WatchedDomain.project_id == deps.rules.project, WatchedDomain.domain == parts.fqdn
            )
            .with_for_update()
        )
        if existing is not None and (existing.expires_at is None or existing.expires_at > now):
            raise HTTPException(409, "already watched")
        if existing is not None:  # 已移出的域名重新加入（例如下架后复活）
            existing.expires_at, existing.next_check_at, existing.reason = None, now, reason
            entry = existing
        else:
            await watchlist.ensure_watched(
                s, deps.rules.project, parts.fqdn, reason=reason, now=now
            )
            entry = (
                await s.scalars(
                    select(WatchedDomain).where(
                        WatchedDomain.project_id == deps.rules.project,
                        WatchedDomain.domain == parts.fqdn,
                    )
                )
            ).one()
        await s.flush()
        await record(
            s,
            request,
            user,
            "watchlist.add",
            target_type="watched_domain",
            target_id=entry.id,
            detail={"domain": parts.fqdn, "reason": body.reason},
        )
        return _out(entry)


@router.delete("/watchlist/{watch_id}", status_code=204)
async def remove_watch(
    watch_id: int,
    request: Request,
    user: Writer,
    reason: Annotated[str, Query(max_length=500)] = "",
) -> Response:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        entry = await s.get(WatchedDomain, watch_id, with_for_update=True)
        if entry is None or entry.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        if entry.expires_at is not None and entry.expires_at <= deps.clock():
            raise HTTPException(409, "already removed")
        entry.expires_at = deps.clock()
        await record(
            s,
            request,
            user,
            "watchlist.remove",
            target_type="watched_domain",
            target_id=entry.id,
            detail={"domain": entry.domain, "reason": reason},
        )
    return Response(status_code=204)


@router.put("/watchlist/{watch_id}")
async def update_watch(watch_id: int, body: WatchIn, request: Request, user: Writer) -> WatchOut:
    parts = parse_domain(body.domain)
    if parts is None:
        raise HTTPException(422, "invalid domain")
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions.begin() as s:
        entry = await s.scalar(
            select(WatchedDomain).where(WatchedDomain.id == watch_id).with_for_update()
        )
        if entry is None or entry.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        if entry.expires_at is not None and entry.expires_at <= now:
            raise HTTPException(409, "already removed")
        old_domain = entry.domain
        reason = _edited_reason(entry.reason, body.reason, user.username)
        if parts.fqdn == old_domain:
            entry.reason = reason
            result = entry
        else:
            # A new domain needs its own row so its observations cannot be
            # mistaken for the old domain's history.
            if not await watchlist.ensure_watched(
                s, deps.rules.project, parts.fqdn, reason=reason, now=now
            ):
                raise HTTPException(409, "domain already watched")
            result = (
                await s.scalars(
                    select(WatchedDomain).where(
                        WatchedDomain.project_id == deps.rules.project,
                        WatchedDomain.domain == parts.fqdn,
                    )
                )
            ).one()
            result.reason = reason
            result.last_checked_at = None
            result.expires_at = entry.expires_at  # 有期限的监视（如下架后 90 天）换域名后期限不变
            entry.expires_at = now
        await s.flush()
        await record(
            s,
            request,
            user,
            "watchlist.update",
            target_type="watched_domain",
            target_id=result.id,
            detail={"old_domain": old_domain, "domain": parts.fqdn, "reason": body.reason},
        )
        return _out(result)


@router.get("/watchlist/{watch_id}/observations")
async def observations(watch_id: int, request: Request, user: Reader) -> list[WatchObservationOut]:
    deps = get_deps(request)
    async with deps.sessions() as s:
        entry = await s.get(WatchedDomain, watch_id)
        if entry is None or entry.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        rows = (
            await s.scalars(
                select(DomainObservation)
                .where(DomainObservation.watched_domain_id == watch_id)
                .order_by(DomainObservation.observed_at.desc())
                .limit(100)
            )
        ).all()
        evidence = await _evidence_for(s, [o.id for o in rows], user)
    return [
        WatchObservationOut(
            id=o.id,
            observed_at=o.observed_at,
            state=o.state,
            changes=list(o.changes),
            fingerprint=dict(o.fingerprint),
            inspection=_inspection(o, evidence.get(o.id, [])),
        )
        for o in rows
    ]


@router.post("/watchlist/{watch_id}/check", status_code=202)
async def check_watch(watch_id: int, request: Request, user: Writer) -> WatchCheckOut:
    deps = get_deps(request)
    if not deps.settings.broker_url:
        raise HTTPException(503, "task queue is not configured")
    async with deps.sessions.begin() as s:
        entry = await s.get(WatchedDomain, watch_id)
        if entry is None or entry.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        if (
            entry.expires_at is not None and entry.expires_at <= deps.clock()
        ) or entry.paused_by_suppression:
            raise HTTPException(409, "watch is inactive")
        checked_at = entry.last_checked_at.isoformat() if entry.last_checked_at else None
        await record(
            s,
            request,
            user,
            "watchlist.check_requested",
            target_type="watched_domain",
            target_id=watch_id,
            detail={"domain": entry.domain},
        )
    try:
        await recheck_watched_domain.kiq(watch_id, checked_at)
    except Exception as exc:
        raise HTTPException(503, "failed to queue watch check") from exc
    return WatchCheckOut(watch_id=watch_id, request_id=request.state.request_id)
