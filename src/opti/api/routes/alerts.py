"""告警队列、详情、状态与研判反馈（设计文档 9.3、14、15）。"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.runtime import active_ticket_client
from opti.api.deps import Principal, get_deps, record, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.api.routes.campaigns import alert_campaign
from opti.api.schemas import (
    AlertDetail,
    AlertHistoryItem,
    AlertPage,
    AlertSummary,
    AlertUpdate,
    EvidenceOut,
    FeedbackIn,
    FeedbackOut,
    FindingOut,
    ObservationOut,
    RelatedAlert,
    TakedownBrief,
    TicketOut,
    WatchBrief,
)
from opti.core.alert_fingerprint import fingerprint
from opti.core.campaign import fingerprints, shared_signals
from opti.db.models import (
    Alert,
    AlertFinding,
    AppUser,
    Entity,
    Evidence,
    Feedback,
    Finding,
    FindingObservation,
    Takedown,
    WatchedDomain,
)
from opti.pipeline import suppression
from opti.pipeline.triage import (
    ACTIVE_STATUSES as DEFAULT_STATUSES,
)
from opti.pipeline.triage import (
    SUPPRESSIBLE_VERDICTS,
    apply_status,
    apply_verdict,
)
from opti.tickets.factory import ticket_url

router = APIRouter(tags=["alerts"])
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
Reader = Annotated[Principal, Depends(require(Perm.ALERTS_READ))]
Triager = Annotated[Principal, Depends(require(Perm.ALERTS_TRIAGE))]


def _screenshot_id() -> Any:
    """本告警的沙箱截图，或同一发现上分析员上传的截图（平台链接升级为新告警后沿用此前的上传）。"""
    return (
        select(func.min(Evidence.id))
        .where(
            or_(
                and_(Evidence.alert_id == Alert.id, Evidence.kind == "screenshot"),
                and_(Evidence.finding_id == Finding.id, Evidence.kind == "upload"),
            )
        )
        .correlate(Alert, Finding)
        .scalar_subquery()
    )


def _base() -> Select[Any]:
    return (
        select(Alert, Finding, _screenshot_id(), Entity.value)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .join(Entity, Entity.id == Finding.entity_id)
    )


def _summary(
    alert: Alert, finding: Finding, screenshot_id: int | None, domain: str
) -> AlertSummary:
    snap = alert.routing if isinstance(alert.routing, dict) else {}  # 开告警时冻结的快照（S1-C）
    return AlertSummary(
        id=alert.id,
        severity=alert.severity,
        status=alert.status,
        ignored=alert.ignored_at is not None,
        ignored_at=alert.ignored_at,
        category=str(snap.get("category") or finding.category),
        domain=str(snap.get("domain") or domain),
        score=int(snap.get("score") or finding.score),
        reasons=[str(r) for r in snap.get("reasons") or []],
        attack_techniques=snap.get("attack_techniques") or [],
        created_at=alert.created_at,
        notified_at=alert.notified_at,
        evidence_status=alert.evidence_status,
        screenshot_id=screenshot_id,
        triage_verdict=alert.triage_verdict,
        finding_id=finding.id,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        sources=list(finding.sources),
    )


def _like(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


async def _load(
    s: AsyncSession, alert_id: int, project_id: str, *, lock: bool = False
) -> tuple[Alert, Finding, int | None, str]:
    stmt = _base().where(Alert.id == alert_id, Alert.project_id == project_id)
    if lock:
        stmt = stmt.with_for_update(of=Alert)
    row = (await s.execute(stmt)).first()
    if row is None:
        raise HTTPException(404, "alert not found")
    return row[0], row[1], row[2], row[3]


async def _related_alerts(
    s: AsyncSession, alert: Alert, finding: Finding, entity: Entity | None
) -> list[RelatedAlert]:
    if entity is None or entity.type != "domain":
        return []
    own = fingerprints(entity.enrichment)
    conditions = []
    if digest := own.get("tls_sha256"):
        conditions.append(Entity.enrichment["tls"]["data"]["sha256"].astext == digest)
    if digest := own.get("favicon_sha256"):
        conditions.append(
            Entity.enrichment["screenshot"]["data"]["favicon"]["sha256"].astext == digest
        )
    if not conditions:
        return []
    rows = (
        await s.execute(
            select(Alert, Finding, Entity)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .join(Finding, Finding.id == AlertFinding.finding_id)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(
                Alert.project_id == alert.project_id,
                Finding.project_id == alert.project_id,
                Alert.status.in_(DEFAULT_STATUSES),
                Finding.id != finding.id,
                Entity.type == "domain",
                or_(*conditions),
            )
            .order_by(Alert.id.desc())
            .limit(20)
        )
    ).all()
    return [
        RelatedAlert(
            id=other.id,
            domain=other_entity.value,
            severity=other.severity,
            status=other.status,
            last_seen=other_finding.last_seen,
            signals=shared_signals(own, fingerprints(other_entity.enrichment)),
        )
        for other, other_finding, other_entity in rows
    ]


@router.get("/alerts")
async def list_alerts(
    request: Request,
    user: Reader,
    status: Annotated[list[str] | None, Query()] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    category: Annotated[str | None, Query(max_length=50)] = None,
    q: Annotated[str | None, Query(max_length=253)] = None,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    assigned_to_me: bool = False,
    order: Literal["newest", "urgency"] = "newest",
    ignored: Literal["exclude", "only", "all"] = "exclude",
) -> AlertPage:
    if order == "urgency" and cursor is not None:
        raise HTTPException(422, "cursor is not supported with order=urgency")
    stmt = _base().where(
        Alert.project_id == get_deps(request).rules.project,
        Alert.status.in_(status or DEFAULT_STATUSES),
    )
    if ignored != "all":
        stmt = stmt.where(
            Alert.ignored_at.is_(None) if ignored == "exclude" else Alert.ignored_at.is_not(None)
        )
    if assigned_to_me:
        stmt = stmt.where(Alert.assignee_id == user.user_id)
    if severity:
        stmt = stmt.where(Alert.severity.in_(severity))
    if category:
        stmt = stmt.where(
            func.coalesce(Alert.routing["category"].astext, Finding.category) == category
        )
    if q:
        stmt = stmt.where(
            func.coalesce(Alert.routing["domain"].astext, Entity.value).ilike(
                _like(q.strip()), escape="\\"
            )
        )
    count_stmt = stmt
    if order == "urgency":
        # 严重程度高的在前，同级别先建的在前（我的待办等场景）
        rank = case(_SEVERITY_RANK, value=Alert.severity, else_=len(_SEVERITY_RANK))
        stmt = (
            stmt.order_by(rank, Alert.created_at, Alert.id)
            .offset(page_offset(page, limit))
            .limit(limit)
        )
        async with get_deps(request).sessions() as s:
            total = await page_total(s, count_stmt, page, cursor)
            rows = (await s.execute(stmt)).all()
        return AlertPage(items=[_summary(*row) for row in rows], next_cursor=None, total=total)
    if cursor is not None:
        stmt = stmt.where(Alert.id < cursor)
    stmt = stmt.order_by(Alert.id.desc()).offset(page_offset(page, limit)).limit(limit + 1)
    async with get_deps(request).sessions() as s:
        total = await page_total(s, count_stmt, page, cursor)
        rows = (await s.execute(stmt)).all()
    items = [_summary(a, f, shot, domain) for a, f, shot, domain in rows[:limit]]
    return AlertPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit and items else None
    )


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int, request: Request, user: Reader) -> AlertDetail:
    async with get_deps(request).sessions.begin() as s:
        alert, finding, shot, domain = await _load(s, alert_id, get_deps(request).rules.project)
        entity = await s.get(Entity, finding.entity_id)
        evidence = (
            await s.scalars(
                select(Evidence)
                .where(Evidence.finding_id == finding.id)
                .order_by(Evidence.captured_at.desc(), Evidence.id.desc())
            )
        ).all()
        observations = (
            await s.scalars(
                select(FindingObservation)
                .where(FindingObservation.finding_id == finding.id)
                .order_by(FindingObservation.observed_at.desc())
                .limit(50)
            )
        ).all()
        feedback = (
            await s.execute(
                select(Feedback, AppUser.username)
                .join(AppUser, AppUser.id == Feedback.user_id)
                .where(Feedback.finding_id == finding.id)
                .order_by(Feedback.created_at.desc())
            )
        ).all()
        history = (
            await s.scalars(
                select(Alert)
                .join(AlertFinding, AlertFinding.alert_id == Alert.id)
                .where(AlertFinding.finding_id == finding.id, Alert.id != alert.id)
                .order_by(Alert.id.desc())
            )
        ).all()
        watch = None
        if entity is not None:
            watch = await s.scalar(
                select(WatchedDomain).where(
                    WatchedDomain.project_id == finding.project_id,
                    WatchedDomain.domain == entity.value,
                )
            )
        assignee = await s.get(AppUser, alert.assignee_id) if alert.assignee_id else None
        uploader_ids = {e.uploaded_by for e in evidence if e.uploaded_by is not None}
        uploaders = (
            dict(
                (
                    await s.execute(
                        select(AppUser.id, AppUser.username).where(AppUser.id.in_(uploader_ids))
                    )
                ).all()
            )
            if uploader_ids
            else {}
        )
        await record(s, request, user, "alert.view", target_type="alert", target_id=alert.id)
        takedowns = (
            await s.scalars(
                select(Takedown).where(Takedown.finding_id == finding.id).order_by(Takedown.id)
            )
        ).all()
        enrichment = dict(entity.enrichment or {}) if entity is not None else {}
        related = (
            await _related_alerts(s, alert, finding, entity)
            if Perm.EVIDENCE_READ in user.perms
            else []
        )
        campaign = (
            await alert_campaign(s, alert.project_id, finding.id)
            if Perm.EVIDENCE_READ in user.perms
            else None
        )
        if Perm.EVIDENCE_READ not in user.perms:
            enrichment.pop("screenshot", None)
        return AlertDetail(
            takedowns=[
                TakedownBrief(
                    id=t.id,
                    state=t.state,
                    target_name=str(t.target.get("name") or ""),
                    target_kind=str(t.target.get("kind") or ""),
                    updated_at=t.updated_at,
                )
                for t in takedowns
            ],
            ticket=TicketOut(
                ref=alert.ticket_ref,
                status=alert.ticket_status,
                pushed_at=alert.ticket_pushed_at,
                synced_at=alert.ticket_synced_at,
                available=active_ticket_client(get_deps(request).tickets) is not None,
                url=ticket_url(get_deps(request).tickets_cfg, alert.ticket_ref),
            ),
            alert=_summary(alert, finding, shot, domain),
            finding=FindingOut(
                id=finding.id,
                category=finding.category,
                score=finding.score,
                severity=finding.severity,
                status=finding.status,
                score_breakdown={k: int(v) for k, v in (finding.score_breakdown or {}).items()},
                match=dict(finding.match or {}),
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                sources=list(finding.sources),
            ),
            enrichment=enrichment,
            observations=[
                ObservationOut(
                    connector_id=o.connector_id, observed_at=o.observed_at, score=o.score
                )
                for o in observations
            ],
            evidence=[
                EvidenceOut(
                    id=e.id,
                    kind=e.kind,
                    content_type=e.content_type,
                    sha256=e.sha256,
                    size=e.size,
                    captured_at=e.captured_at,
                    node_id=e.node_id,
                    method=e.method,
                    source_url=e.source_url,
                    uploaded_by=uploaders.get(e.uploaded_by) if e.uploaded_by else None,
                    original_sha256=e.original_sha256,
                )
                for e in evidence
            ],
            feedback=[
                FeedbackOut(
                    verdict=f.verdict, reason=f.reason, username=name, created_at=f.created_at
                )
                for f, name in feedback
            ],
            history=[
                AlertHistoryItem(
                    id=h.id, severity=h.severity, status=h.status, created_at=h.created_at
                )
                for h in history
            ],
            related_alerts=related,
            campaign=campaign,
            watch=(
                WatchBrief(
                    id=watch.id,
                    state=watch.state,
                    next_check_at=watch.next_check_at,
                    last_checked_at=watch.last_checked_at,
                    expires_at=watch.expires_at,
                )
                if watch is not None
                else None
            ),
            assignee=assignee.username if assignee is not None else None,
            entity_type=entity.type if entity is not None else "domain",
            translation_available=get_deps(request).translator is not None,
        )


@router.patch("/alerts/{alert_id}")
async def update_alert(
    alert_id: int, body: AlertUpdate, request: Request, user: Triager
) -> AlertSummary:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        alert, finding, shot, domain = await _load(s, alert_id, deps.rules.project, lock=True)
        if alert.status == "superseded":
            raise HTTPException(409, "alert superseded by a newer alert")
        now = deps.clock()
        before = {
            "status": alert.status,
            "assignee_id": alert.assignee_id,
            "ignored": alert.ignored_at is not None,
        }
        if body.ignored is True:
            if alert.status not in DEFAULT_STATUSES or body.status == "closed":
                raise HTTPException(409, "only active alerts can be ignored")
            if alert.ignored_at is None:
                entity = await s.get(Entity, finding.entity_id)
                alert.ignored_at = now
                alert.ignored_fingerprint = fingerprint(
                    finding.category,
                    finding.severity,
                    finding.match,
                    entity.enrichment if entity is not None else {},
                )
        elif body.ignored is False:
            alert.ignored_at, alert.ignored_fingerprint = None, {}
        if body.status is not None:
            apply_status(alert, body.status, now)
        if body.assign_to_me is not None:
            alert.assignee_id = user.user_id if body.assign_to_me else None
        alert.updated_at = now
        after = {
            "status": alert.status,
            "assignee_id": alert.assignee_id,
            "ignored": alert.ignored_at is not None,
        }
        await record(
            s,
            request,
            user,
            "alert.update",
            target_type="alert",
            target_id=alert.id,
            detail={"before": before, "after": after},
        )
        return _summary(alert, finding, shot, domain)


@router.post("/alerts/{alert_id}/feedback")
async def submit_feedback(
    alert_id: int, body: FeedbackIn, request: Request, user: Triager
) -> AlertSummary:
    if body.suppress != "none" and body.verdict not in SUPPRESSIBLE_VERDICTS:
        raise HTTPException(
            422, "only false_positive or benign_known can create a suppression rule"
        )
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        alert, finding, shot, domain = await _load(s, alert_id, deps.rules.project, lock=True)
        now = deps.clock()
        apply_verdict(
            s, alert, finding.id, user_id=user.user_id, verdict=body.verdict,
            reason=body.reason, now=now,
        )  # fmt: skip
        detail: dict[str, Any] = {"verdict": body.verdict, "reason": body.reason}
        if body.suppress != "none":
            entity = await s.get(Entity, finding.entity_id)
            if entity is None:
                raise HTTPException(409, "entity missing")
            if entity.type != "domain":
                raise HTTPException(422, "only domain entities can create domain suppression rules")
            expires = now + timedelta(days=body.suppress_days) if body.suppress_days else None
            try:
                rule = await suppression.create_rule(
                    s,
                    project_id=alert.project_id,
                    kind=body.suppress,
                    value=entity.value,
                    reason=body.reason or body.verdict,
                    now=now,
                    created_by=user.user_id,
                    source_alert_id=alert.id,
                    expires_at=expires,
                )
            except suppression.SuppressionError as e:
                raise HTTPException(422, str(e)) from e
            closed = await suppression.close_covered_alerts(
                s, rule, now=now, exclude_alert_id=alert.id
            )
            await record(
                s,
                request,
                user,
                "suppression.create",
                target_type="suppression_rule",
                target_id=rule.id,
                detail={
                    "kind": rule.kind,
                    "value": rule.value,
                    "source_alert_id": alert.id,
                    "closed_alerts": closed,
                },
            )
            detail["suppression_rule_id"] = rule.id
        await record(
            s,
            request,
            user,
            "alert.feedback",
            target_type="alert",
            target_id=alert.id,
            detail=detail,
        )
        return _summary(alert, finding, shot, domain)
