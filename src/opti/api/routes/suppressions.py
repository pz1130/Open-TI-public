"""抑制规则管理（设计文档 6.2、9.3）。"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import aliased

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import SuppressionIn, SuppressionOut
from opti.db import repo
from opti.db.models import AppUser, SuppressionRule
from opti.pipeline import suppression

router = APIRouter(tags=["suppressions"])
Reader = Annotated[Principal, Depends(require(Perm.SUPPRESSIONS_READ))]
Writer = Annotated[Principal, Depends(require(Perm.SUPPRESSIONS_WRITE))]


def _out(rule: SuppressionRule, creator: str | None, now: datetime) -> SuppressionOut:
    active = rule.revoked_at is None and (rule.expires_at is None or rule.expires_at > now)
    return SuppressionOut(
        id=rule.id,
        kind=rule.kind,
        value=rule.value,
        reason=rule.reason,
        created_by=creator,
        source_alert_id=rule.source_alert_id,
        created_at=rule.created_at,
        expires_at=rule.expires_at,
        revoked_at=rule.revoked_at,
        active=active,
    )


@router.get("/suppressions")
async def list_rules(
    request: Request, user: Reader, include_inactive: bool = False
) -> list[SuppressionOut]:
    deps = get_deps(request)
    now = deps.clock()
    creator = aliased(AppUser)
    stmt = (
        select(SuppressionRule, creator.username)
        .outerjoin(creator, creator.id == SuppressionRule.created_by)
        .where(SuppressionRule.project_id == deps.rules.project)
        .order_by(SuppressionRule.created_at.desc(), SuppressionRule.id.desc())
    )
    if not include_inactive:
        stmt = stmt.where(
            SuppressionRule.revoked_at.is_(None),
            or_(SuppressionRule.expires_at.is_(None), SuppressionRule.expires_at > now),
        )
    async with deps.sessions() as s:
        rows = (await s.execute(stmt)).all()
    return [_out(r, name, now) for r, name in rows]


@router.post("/suppressions", status_code=201)
async def create(body: SuppressionIn, request: Request, user: Writer) -> SuppressionOut:
    deps = get_deps(request)
    now = deps.clock()
    expires = now + timedelta(days=body.expires_days) if body.expires_days else None
    async with deps.sessions.begin() as s:
        await repo.upsert_project(s, deps.rules)
        try:
            rule = await suppression.create_rule(
                s,
                project_id=deps.rules.project,
                kind=body.kind,
                value=body.value,
                reason=body.reason,
                now=now,
                created_by=user.user_id,
                expires_at=expires,
            )
        except suppression.SuppressionError as e:
            raise HTTPException(422, str(e)) from e
        closed = await suppression.close_covered_alerts(s, rule, now=now)
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
                "reason": rule.reason,
                "closed_alerts": closed,
            },
        )
        return _out(rule, user.username, now)


@router.delete("/suppressions/{rule_id}", status_code=204)
async def revoke(rule_id: int, request: Request, user: Writer) -> Response:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        rule = await suppression.revoke(s, rule_id, user_id=user.user_id, now=deps.clock())
        if rule is None or rule.project_id != deps.rules.project:
            raise HTTPException(404, "not found or already revoked")
        await record(
            s,
            request,
            user,
            "suppression.revoke",
            target_type="suppression_rule",
            target_id=rule.id,
            detail={"kind": rule.kind, "value": rule.value},
        )
    return Response(status_code=204)
