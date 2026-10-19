"""仿冒活动（设计文档 8 实体聚类）：查看、确认与驳回、成员决定、批量研判。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import (
    AlertCampaign,
    CampaignBulk,
    CampaignBulkOut,
    CampaignDetail,
    CampaignIgnored,
    CampaignLink,
    CampaignMemberOut,
    CampaignPage,
    CampaignState,
    CampaignSummary,
    CampaignUpdate,
    MemberDecision,
)
from opti.core.campaign import GROUP_SIGNALS
from opti.core.scoring import severity_rank
from opti.db.models import (
    Alert,
    AlertFinding,
    AppUser,
    Campaign,
    CampaignMember,
    Entity,
    Finding,
    Takedown,
)
from opti.pipeline import campaigns
from opti.pipeline.triage import ACTIVE_STATUSES, apply_status, apply_verdict

router = APIRouter(tags=["campaigns"])
Viewer = Annotated[Principal, Depends(require(Perm.EVIDENCE_READ))]
Triager = Annotated[Principal, Depends(require(Perm.ALERTS_TRIAGE))]
MAX_BULK = 500


def _check_read(user: Principal) -> None:
    if Perm.ALERTS_READ not in user.perms:
        raise HTTPException(403, "forbidden")


async def _get(
    s: AsyncSession, campaign_id: int, project_id: str, *, lock: bool = False
) -> Campaign:
    stmt = select(Campaign).where(Campaign.id == campaign_id, Campaign.project_id == project_id)
    if lock:
        stmt = stmt.with_for_update()
    campaign = await s.scalar(stmt)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    return campaign


async def _views(
    s: AsyncSession, items: list[Campaign]
) -> dict[int, tuple[CampaignSummary, list[CampaignMemberOut]]]:
    ids = [c.id for c in items]
    if not ids:
        return {}
    rows = (
        await s.execute(
            select(CampaignMember, Entity.type, Entity.value)
            .join(Finding, Finding.id == CampaignMember.finding_id)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(CampaignMember.campaign_id.in_(ids))
            .order_by(CampaignMember.campaign_id, Finding.first_seen, CampaignMember.finding_id)
        )
    ).all()
    fids = sorted({m.finding_id for m, _, _ in rows})
    latest: dict[int, Alert] = {}
    takedowns: dict[int, str] = {}
    if fids:
        for fid, alert in (
            await s.execute(
                select(AlertFinding.finding_id, Alert)
                .join(Alert, Alert.id == AlertFinding.alert_id)
                .where(AlertFinding.finding_id.in_(fids), Alert.status != "superseded")
                .order_by(AlertFinding.finding_id, Alert.id.desc())
                .ext(distinct_on(AlertFinding.finding_id))
            )
        ).all():
            latest[fid] = alert
        for fid, state in (
            await s.execute(
                select(Takedown.finding_id, Takedown.state)
                .where(Takedown.finding_id.in_(fids))
                .order_by(Takedown.finding_id, Takedown.id.desc())
                .ext(distinct_on(Takedown.finding_id))
            )
        ).all():
            takedowns[fid] = state
    assignees = {a.assignee_id for a in latest.values() if a.assignee_id is not None}
    users: dict[int, str] = {}
    if assignees:
        for uid, username in (
            await s.execute(select(AppUser.id, AppUser.username).where(AppUser.id.in_(assignees)))
        ).all():
            users[uid] = username
    members: dict[int, list[CampaignMemberOut]] = {i: [] for i in ids}
    for m, entity_type, value in rows:
        current = latest.get(m.finding_id)
        members[m.campaign_id].append(
            CampaignMemberOut(
                finding_id=m.finding_id,
                entity_type=entity_type,
                value=value,
                state=m.state,  # type: ignore[arg-type]
                signals=[CampaignLink.model_validate(link) for link in m.signals],
                alert_id=current.id if current else None,
                severity=current.severity if current else None,
                status=current.status if current else None,
                assignee=users.get(current.assignee_id)
                if current and current.assignee_id
                else None,
                verdict=current.triage_verdict if current else None,
                takedown_state=takedowns.get(m.finding_id),
                added_at=m.added_at,
            )
        )
    out: dict[int, tuple[CampaignSummary, list[CampaignMemberOut]]] = {}
    for c in items:
        ms = members[c.id]
        live = [m for m in ms if m.state != "excluded"]
        active = [m for m in live if m.status in ACTIVE_STATUSES]
        kinds = {link.kind for m in live for link in m.signals}
        severities = [m.severity for m in active if m.severity]
        summary = CampaignSummary(
            id=c.id,
            state=c.state,  # type: ignore[arg-type]
            name=c.name,
            label_value=(live or ms)[0].value if ms else "",
            member_count=sum(m.state == "member" for m in ms),
            pending_count=sum(m.state == "pending" for m in ms),
            active_alerts=len(active),
            top_severity=max(severities, key=severity_rank) if severities else None,
            signal_kinds=[k for k in GROUP_SIGNALS if k in kinds],
            updated_at=c.updated_at,
        )
        out[c.id] = (summary, ms)
    return out


async def alert_campaign(s: AsyncSession, project_id: str, finding_id: int) -> AlertCampaign | None:
    row = (
        await s.execute(
            select(Campaign, CampaignMember.state)
            .join(CampaignMember, CampaignMember.campaign_id == Campaign.id)
            .where(
                Campaign.project_id == project_id,
                Campaign.state == "confirmed",
                CampaignMember.finding_id == finding_id,
                CampaignMember.state.in_(("member", "pending")),
            )
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    campaign, member_state = row
    summary, _ = (await _views(s, [campaign]))[campaign.id]
    return AlertCampaign(
        id=campaign.id,
        name=campaign.name,
        label_value=summary.label_value,
        member_count=summary.member_count,
        state="confirmed",
        member_state=member_state,  # type: ignore[arg-type]
    )


@router.get("/campaigns")
async def list_campaigns(
    request: Request,
    user: Viewer,
    state: Annotated[CampaignState, Query()] = "candidate",
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CampaignPage:
    _check_read(user)
    deps = get_deps(request)
    where = (Campaign.project_id == deps.rules.project, Campaign.state == state)
    async with deps.sessions.begin() as s:
        total = await s.scalar(select(func.count()).select_from(Campaign).where(*where)) or 0
        items = list(
            (
                await s.scalars(
                    select(Campaign)
                    .where(*where)
                    .order_by(Campaign.updated_at.desc(), Campaign.id.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            ).all()
        )
        views = await _views(s, items)
        return CampaignPage(items=[views[c.id][0] for c in items], total=total)


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int, request: Request, user: Viewer) -> CampaignDetail:
    _check_read(user)
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        campaign = await _get(s, campaign_id, deps.rules.project)
        summary, members = (await _views(s, [campaign]))[campaign.id]
        confirmed_by = (
            await s.scalar(select(AppUser.username).where(AppUser.id == campaign.confirmed_by))
            if campaign.confirmed_by is not None
            else None
        )
        return CampaignDetail(
            campaign=summary,
            note=campaign.note,
            ignored=[CampaignIgnored.model_validate(i) for i in campaign.ignored],
            confirmed_at=campaign.confirmed_at,
            confirmed_by=confirmed_by,
            members=members,
        )


def _snapshot(campaign: Campaign) -> dict[str, object]:
    return {"state": campaign.state, "name": campaign.name, "note_length": len(campaign.note)}


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(
    campaign_id: int, body: CampaignUpdate, request: Request, user: Triager
) -> CampaignSummary:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await campaigns.lock(s)
        campaign = await _get(s, campaign_id, deps.rules.project, lock=True)
        now = deps.clock()
        before = _snapshot(campaign)
        if body.state is not None and body.state != campaign.state:
            try:
                await campaigns.transition(s, campaign, body.state, user_id=user.user_id, now=now)
            except campaigns.CampaignError as e:
                raise HTTPException(e.status, str(e)) from e
        if body.name is not None:
            campaign.name = body.name.strip() or None
        if body.note is not None:
            campaign.note = body.note
        campaign.updated_at = now
        await record(
            s, request, user, "campaign.update", target_type="campaign", target_id=campaign.id,
            detail={"before": before, "after": _snapshot(campaign)},
        )  # fmt: skip
        await s.flush()
        return (await _views(s, [campaign]))[campaign.id][0]


@router.post("/campaigns/{campaign_id}/members/{finding_id}")
async def decide_member(
    campaign_id: int, finding_id: int, body: MemberDecision, request: Request, user: Triager
) -> CampaignSummary:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await campaigns.lock(s)
        campaign = await _get(s, campaign_id, deps.rules.project, lock=True)
        try:
            await campaigns.decide(
                s, campaign, finding_id, body.decision, user_id=user.user_id, now=deps.clock()
            )
        except campaigns.CampaignError as e:
            raise HTTPException(e.status, str(e)) from e
        await record(
            s, request, user, "campaign.member", target_type="campaign", target_id=campaign.id,
            detail={"finding_id": finding_id, "decision": body.decision},
        )  # fmt: skip
        return (await _views(s, [campaign]))[campaign.id][0]


@router.post("/campaigns/{campaign_id}/bulk")
async def bulk_triage(
    campaign_id: int, body: CampaignBulk, request: Request, user: Triager
) -> CampaignBulkOut:
    if body.action == "verdict" and body.verdict is None:
        raise HTTPException(422, "verdict is required")
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await campaigns.lock(s)
        campaign = await _get(s, campaign_id, deps.rules.project, lock=True)
        if campaign.state != "confirmed":
            raise HTTPException(409, "campaign not confirmed")
        finding_ids = list(
            (
                await s.scalars(
                    select(CampaignMember.finding_id).where(
                        CampaignMember.campaign_id == campaign.id,
                        CampaignMember.state == "member",
                    )
                )
            ).all()
        )
        rows = (
            await s.execute(
                select(Alert, AlertFinding.finding_id)
                .join(AlertFinding, AlertFinding.alert_id == Alert.id)
                .where(
                    AlertFinding.finding_id.in_(finding_ids),
                    Alert.project_id == deps.rules.project,
                    Alert.status.in_(ACTIVE_STATUSES),
                )
                .order_by(Alert.id)
                .with_for_update(of=Alert)
            )
        ).all()
        if len(rows) > MAX_BULK:
            raise HTTPException(422, f"bulk action limited to {MAX_BULK} alerts")
        now = deps.clock()
        updated: list[int] = []
        for alert, finding_id in rows:
            if body.action == "verdict":
                assert body.verdict is not None
                apply_verdict(
                    s, alert, finding_id, user_id=user.user_id, verdict=body.verdict,
                    reason=body.reason, now=now,
                )  # fmt: skip
                await record(
                    s, request, user, "alert.feedback", target_type="alert", target_id=alert.id,
                    detail={"verdict": body.verdict, "reason": body.reason, "campaign_id": campaign.id},
                )  # fmt: skip
            else:
                target = "acknowledged" if body.action == "acknowledge" else "closed"
                if alert.status == target:
                    continue
                before = {"status": alert.status, "assignee_id": alert.assignee_id}
                apply_status(alert, target, now)
                await record(
                    s, request, user, "alert.update", target_type="alert", target_id=alert.id,
                    detail={
                        "before": before,
                        "after": {"status": alert.status, "assignee_id": alert.assignee_id},
                        "campaign_id": campaign.id,
                    },
                )  # fmt: skip
            updated.append(alert.id)
        skipped = len(finding_ids) - len(updated)
        campaign.updated_at = now
        await record(
            s, request, user, "campaign.bulk", target_type="campaign", target_id=campaign.id,
            detail={"action": body.action, "verdict": body.verdict, "alerts": updated, "skipped": skipped},
        )  # fmt: skip
        return CampaignBulkOut(updated=updated, skipped=skipped)
