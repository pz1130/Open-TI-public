"""下架跟踪（设计文档 12.1、14、15）：投诉对象、材料、审批、状态、证据包与 .eml。平台不自动发送投诉。"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.deps import ApiDeps, CurrentUser, Principal, get_deps, record, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.api.schemas import (
    TakedownDetail,
    TakedownEdit,
    TakedownEventOut,
    TakedownIn,
    TakedownOut,
    TakedownPage,
    TakedownStats,
    TakedownTransition,
    TargetOut,
    TargetsOut,
)
from opti.db.models import (
    Alert,
    AlertFinding,
    AppUser,
    Entity,
    Evidence,
    Finding,
    Takedown,
    TakedownEvent,
)
from opti.takedown import hosting
from opti.takedown import service as takedown_service
from opti.takedown.bundle import BundleError, build_eml, evidence_bundle
from opti.takedown.render import EvidenceLine, TemplateError, build_context, render
from opti.takedown.service import Actor, TakedownError
from opti.takedown.stats import StatRow, compute
from opti.takedown.targets import Target, TargetList, discover, escalations

router = APIRouter(tags=["takedowns"])
Reader = Annotated[Principal, Depends(require(Perm.TAKEDOWN_READ))]
Drafter = Annotated[Principal, Depends(require(Perm.TAKEDOWN_DRAFT))]
Exporter = Annotated[Principal, Depends(require(Perm.EVIDENCE_EXPORT))]
EML_STATES = ("approved", "submitted", "acknowledged")


def _err(e: TakedownError | BundleError) -> HTTPException:
    return HTTPException(e.status, e.message)


def _target_out(t: Target) -> TargetOut:
    return TargetOut(**t.to_dict())


def _actor(user: Principal) -> Actor:
    return Actor(user.user_id, user.username)


async def _alert(s: AsyncSession, alert_id: int, project: str) -> tuple[Alert, Finding, Entity]:
    row = (
        await s.execute(
            select(Alert, Finding, Entity)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .join(Finding, Finding.id == AlertFinding.finding_id)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(Alert.id == alert_id, Alert.project_id == project)
        )
    ).first()
    if row is None:
        raise HTTPException(404, "alert not found")
    return row[0], row[1], row[2]


def _first_seen(recorded: datetime, manual: Mapping[str, Any]) -> datetime:
    """分析员填写的发现时间早于平台记录时，以分析员看到线索的时间为准。"""
    raw = manual.get("observed_at")
    try:
        seen = datetime.fromisoformat(str(raw)) if raw else None
    except ValueError:
        seen = None
    return seen if seen is not None and seen.tzinfo is not None and seen < recorded else recorded


async def _evidence(s: AsyncSession, finding_id: int) -> list[Evidence]:
    stmt = (
        select(Evidence)
        .where(Evidence.finding_id == finding_id)
        .order_by(Evidence.captured_at.desc(), Evidence.id.desc())
        .limit(20)
    )
    return list((await s.scalars(stmt)).all())


async def _usernames(s: AsyncSession, ids: Iterable[int | None]) -> dict[int, str]:
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    rows = await s.execute(select(AppUser.id, AppUser.username).where(AppUser.id.in_(wanted)))
    return {uid: name for uid, name in rows.all()}


def _out(td: Takedown, names: dict[int, str]) -> TakedownOut:
    return TakedownOut(
        id=td.id, alert_id=td.alert_id, domain=td.domain, target=_target_out(Target.from_dict(td.target)),
        language=td.language, subject=td.subject, body=td.body, state=td.state,
        created_by=names.get(td.created_by, "?"),
        approved_by=names.get(td.approved_by) if td.approved_by is not None else None,
        external_ref=td.external_ref, created_at=td.created_at, updated_at=td.updated_at,
        submitted_at=td.submitted_at, resolved_at=td.resolved_at, due_at=td.due_at,
        reminders=td.reminders, reappeared_alert_id=td.reappeared_alert_id,
    )  # fmt: skip


async def _load(s: AsyncSession, takedown_id: int, project: str, *, lock: bool = False) -> Takedown:
    stmt = select(Takedown).where(Takedown.id == takedown_id, Takedown.project_id == project)
    if lock:
        stmt = stmt.with_for_update()
    td = await s.scalar(stmt)
    if td is None:
        raise HTTPException(404, "takedown not found")
    return td


async def _targets(
    s: AsyncSession, deps: ApiDeps, entity: Entity
) -> tuple[TargetList, hosting.HostData]:
    if hosting.alert_host(entity.type, entity.value) is None:
        raise HTTPException(409, "only domain and URL alerts support takedowns")
    data = await hosting.load_host_data(s, entity)
    return discover(deps.takedown, data), data


@router.get("/alerts/{alert_id}/takedown-targets")
async def takedown_targets(alert_id: int, request: Request, user: Drafter) -> TargetsOut:
    deps = get_deps(request)
    async with deps.sessions() as s:
        _, _, entity = await _alert(s, alert_id, deps.rules.project)
        found, _ = await _targets(s, deps, entity)
    return TargetsOut(
        host=found.host,
        targets=[_target_out(t) for t in found.targets],
        missing_hosting=found.missing_hosting,
    )


@router.post("/alerts/{alert_id}/takedowns", status_code=201)
async def create_takedown(
    alert_id: int, body: TakedownIn, request: Request, user: Drafter
) -> TakedownOut:
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions.begin() as s:
        alert, finding, entity = await _alert(s, alert_id, deps.rules.project)
        found, data = await _targets(s, deps, entity)
        # 联系方式只由服务端根据富化结果重新计算，从不接受前端传来的邮箱
        target = found.get(body.target_id)
        if target is None:
            raise HTTPException(422, "unknown takedown target for this alert")
        snap = alert.routing if isinstance(alert.routing, dict) else {}
        url = (
            entity.value
            if entity.type == "url"
            else snap.get("url")
            if isinstance(snap.get("url"), str)
            else None
        )
        evidence = await _evidence(s, finding.id)
        raw_manual = finding.match.get("manual")
        manual: Mapping[str, Any] = raw_manual if isinstance(raw_manual, dict) else {}
        try:
            ctx = build_context(
                deps.organization, target, language=body.language, host=found.host, url=url,
                category=str(snap.get("category") or finding.category), first_seen=_first_seen(finding.first_seen, manual),
                evidence=[EvidenceLine(e.kind, e.captured_at, e.sha256, e.source_url) for e in evidence],
                ips=list(data.ips), now=now,
                detail=str(manual.get("description") or ""),
            )  # fmt: skip
            material = render(
                deps.config.snapshot.takedown_templates, body.language, target.kind, ctx
            )
        except TemplateError as e:
            raise HTTPException(503, f"takedown templates are not usable: {e}") from e
        try:
            td = await takedown_service.create(
                s, project_id=alert.project_id, alert_id=alert.id, finding_id=finding.id, host=found.host,
                target=target, material=material, language=body.language, actor=_actor(user), now=now,
            )  # fmt: skip
        except TakedownError as e:
            raise _err(e) from e
        await record(
            s, request, user, "takedown.create", target_type="takedown", target_id=td.id,
            detail={"alert_id": alert.id, "target": target.id, "language": body.language},
        )  # fmt: skip
        return _out(td, {user.user_id: user.username})


@router.get("/takedowns")
async def list_takedowns(
    request: Request,
    user: Reader,
    state: Annotated[list[str] | None, Query()] = None,
    alert_id: Annotated[int | None, Query(ge=1)] = None,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TakedownPage:
    deps = get_deps(request)
    stmt = select(Takedown).where(Takedown.project_id == deps.rules.project)
    if state:
        stmt = stmt.where(Takedown.state.in_(state))
    if alert_id is not None:
        stmt = stmt.where(Takedown.alert_id == alert_id)
    count_stmt = stmt
    if cursor is not None:
        stmt = stmt.where(Takedown.id < cursor)
    stmt = stmt.order_by(Takedown.id.desc()).offset(page_offset(page, limit)).limit(limit + 1)
    async with deps.sessions() as s:
        total = await page_total(s, count_stmt, page, cursor)
        rows = (await s.scalars(stmt)).all()
        names = await _usernames(s, [i for td in rows for i in (td.created_by, td.approved_by)])
    items = [_out(td, names) for td in rows[:limit]]
    return TakedownPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit and items else None
    )


# 必须在 /takedowns/{takedown_id} 之前注册：路径参数会先匹配 "stats" 再因类型校验失败返回 422
@router.get("/takedowns/stats")
async def takedown_stats(request: Request, user: Reader) -> TakedownStats:
    deps = get_deps(request)
    async with deps.sessions() as s:
        rows = (
            await s.execute(
                select(Takedown, Finding.first_seen)
                .join(Finding, Finding.id == Takedown.finding_id)
                .where(Takedown.project_id == deps.rules.project)
            )
        ).all()
    stats = compute(
        [
            StatRow(
                td.state, str(td.target.get("name") or ""), str(td.target.get("kind") or ""),
                td.submitted_at, td.acknowledged_at, td.resolved_at, first_seen,
            )
            for td, first_seen in rows
        ]
    )  # fmt: skip
    return TakedownStats.model_validate(stats)


@router.get("/takedowns/{takedown_id}")
async def get_takedown(takedown_id: int, request: Request, user: Reader) -> TakedownDetail:
    deps = get_deps(request)
    async with deps.sessions() as s:
        td = await _load(s, takedown_id, deps.rules.project)
        events = (
            await s.scalars(
                select(TakedownEvent)
                .where(TakedownEvent.takedown_id == td.id)
                .order_by(TakedownEvent.id)
            )
        ).all()
        names = await _usernames(s, [td.created_by, td.approved_by])
    return TakedownDetail(
        takedown=_out(td, names),
        events=[
            TakedownEventOut(
                ts=e.ts, actor=e.actor, from_state=e.from_state, to_state=e.to_state, note=e.note
            )
            for e in events
        ],
        escalation=[_target_out(t) for t in escalations(deps.takedown, str(td.target.get("kind")))],
    )


@router.patch("/takedowns/{takedown_id}")
async def edit_takedown(
    takedown_id: int, body: TakedownEdit, request: Request, user: Drafter
) -> TakedownOut:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        td = await _load(s, takedown_id, deps.rules.project, lock=True)
        before = td.state
        try:
            await takedown_service.edit(
                s, td, subject=body.subject, body=body.body, actor=_actor(user), now=deps.clock()
            )
        except TakedownError as e:
            raise _err(e) from e
        await record(
            s, request, user, "takedown.edit", target_type="takedown", target_id=td.id,
            detail={"state_before": before, "state_after": td.state,
                    "body_sha256": hashlib.sha256(body.body.encode()).hexdigest()},
        )  # fmt: skip
        return _out(td, await _usernames(s, [td.created_by, td.approved_by]))


@router.post("/takedowns/{takedown_id}/transition")
async def transition_takedown(
    takedown_id: int, body: TakedownTransition, request: Request, user: CurrentUser
) -> TakedownOut:
    needed = Perm.TAKEDOWN_APPROVE if body.to == "approved" else Perm.TAKEDOWN_DRAFT
    if needed not in user.perms:
        raise HTTPException(403, "forbidden")
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        td = await _load(s, takedown_id, deps.rules.project, lock=True)
        before = td.state
        try:
            await takedown_service.transition(
                s, td, body.to, actor=_actor(user), now=deps.clock(), cfg=deps.takedown,
                note=body.note, external_ref=body.external_ref,
            )  # fmt: skip
        except TakedownError as e:
            raise _err(e) from e
        await record(
            s, request, user, "takedown.transition", target_type="takedown", target_id=td.id,
            detail={"from": before, "to": td.state, "note": body.note, "external_ref": td.external_ref},
        )  # fmt: skip
        return _out(td, await _usernames(s, [td.created_by, td.approved_by]))


@router.get("/takedowns/{takedown_id}/eml", response_class=Response)
async def takedown_eml(takedown_id: int, request: Request, user: Drafter) -> Response:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        td = await _load(s, takedown_id, deps.rules.project)
        if td.state not in EML_STATES:
            raise HTTPException(409, "the takedown must be approved before it can be exported")
        try:
            data = await build_eml(
                deps.store, deps.organization, td, await _evidence(s, td.finding_id)
            )
        except BundleError as e:
            raise _err(e) from e
        await record(
            s, request, user, "takedown.export_eml", target_type="takedown", target_id=td.id,
            detail={"to": td.target.get("email"), "sha256": hashlib.sha256(data).hexdigest()},
        )  # fmt: skip
    headers = {
        "Content-Disposition": f'attachment; filename="takedown-{td.id}.eml"',
        "Cache-Control": "private, no-store",
    }
    return Response(data, media_type="message/rfc822", headers=headers)


@router.get("/alerts/{alert_id}/evidence-bundle", response_class=Response)
async def alert_evidence_bundle(alert_id: int, request: Request, user: Exporter) -> Response:
    deps = get_deps(request)
    if deps.store is None:
        raise HTTPException(503, "object store not configured")
    async with deps.sessions.begin() as s:
        alert, finding, entity = await _alert(s, alert_id, deps.rules.project)
        evidence = await _evidence(s, finding.id)
        try:
            data = await evidence_bundle(
                deps.store,
                alert=alert,
                finding=finding,
                entity=entity,
                evidence=evidence,
                now=deps.clock(),
                uploaders=await _usernames(s, [e.uploaded_by for e in evidence]),
            )
        except BundleError as e:
            raise _err(e) from e
        await record(
            s, request, user, "evidence.bundle", target_type="alert", target_id=alert.id,
            detail={"files": len(evidence), "sha256": hashlib.sha256(data).hexdigest()},
        )  # fmt: skip
    headers = {
        "Content-Disposition": f'attachment; filename="evidence-alert-{alert_id}.zip"',
        "Cache-Control": "private, no-store",
    }
    return Response(data, media_type="application/zip", headers=headers)
