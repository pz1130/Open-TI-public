"""受保护社交账号管理与冒充候选查看，沿用监视列表权限及审计。"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, StrictBool, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.deps import Principal, get_deps, record, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.configs import connector_edits as edits
from opti.core.scoring import ACCOUNT_SIGNALS, severity_for
from opti.core.social import normalize_handle, normalize_name
from opti.db import repo
from opti.db.models import AccountCandidate, AlertFinding, ProtectedAccount
from opti.pipeline.social_accounts import ADAPTERS, LEASE
from opti.pipeline.tasks import check_protected_account

router = APIRouter(tags=["social-accounts"])
Reader = Annotated[Principal, Depends(require(Perm.WATCHLIST_READ))]
Writer = Annotated[Principal, Depends(require(Perm.WATCHLIST_WRITE))]
Platform = Literal["bluesky", "mastodon"]
MIN_SEVERITY = {"low": 20, "medium": 40, "high": 65, "critical": 85}


class ProtectedAccountIn(BaseModel):
    platform: Platform
    handle: str = Field(min_length=3, max_length=300)
    label: str = Field(default="", max_length=100)
    extra_queries: list[str] = Field(default_factory=list, max_length=5)
    allowed_accounts: list[str] = Field(default_factory=list, max_length=50)
    enabled: StrictBool = True

    @model_validator(mode="after")
    def normalize(self) -> ProtectedAccountIn:
        self.handle = normalize_handle(self.platform, self.handle)
        self.label = self.label.strip()
        queries: dict[str, str] = {}
        for raw in self.extra_queries:
            query = " ".join(raw.split())
            if len(query) > 100 or len(normalize_name(query)) < 2:
                raise ValueError("补充搜索词须为 2–100 个字")
            queries.setdefault(normalize_name(query), query)
        self.extra_queries = list(queries.values())
        allowed = [item.strip().removeprefix("@").lower() for item in self.allowed_accounts]
        if any(not item or len(item) > 300 for item in allowed):
            raise ValueError("已知合法账号须为 1–300 个字")
        self.allowed_accounts = list(dict.fromkeys(allowed))
        return self


class ProtectedAccountOut(BaseModel):
    id: int
    platform: str
    handle: str
    label: str
    extra_queries: list[str]
    allowed_accounts: list[str]
    enabled: bool
    platform_id: str | None
    display_name: str | None
    has_avatar: bool
    profile_checked_at: datetime | None
    created_at: datetime
    next_check_at: datetime
    last_checked_at: datetime | None
    scanning: bool
    error: str | None
    adapter_ready: bool
    candidate_count: int


class ProtectedAccountPage(BaseModel):
    items: list[ProtectedAccountOut]
    next_cursor: int | None
    total: int = 0


class AccountCandidateOut(BaseModel):
    id: int
    platform_account_id: str
    handle: str
    display_name: str
    profile_url: str
    registered_at: datetime | None
    score: int
    severity: str
    signals: list[str]
    first_seen: datetime
    last_seen: datetime
    gone_at: datetime | None
    finding_id: int | None
    alert_id: int | None
    allowed: bool


class AccountCandidatePage(BaseModel):
    items: list[AccountCandidateOut]
    next_cursor: int | None
    total: int = 0


def _adapter_ready(request: Request, platform: str) -> bool:
    deps = get_deps(request)
    eid = ADAPTERS[platform]
    instance = edits.entry(deps.config.snapshot.connectors, eid, deps.settings.config_dir)
    return instance.enabled and instance.license_approved


def _out(request: Request, row: ProtectedAccount, count: int = 0) -> ProtectedAccountOut:
    now = get_deps(request).clock()
    return ProtectedAccountOut(
        id=row.id,
        platform=row.platform,
        handle=row.handle,
        label=row.label,
        extra_queries=row.extra_queries,
        allowed_accounts=row.allowed_accounts,
        enabled=row.enabled,
        platform_id=row.platform_id,
        display_name=row.display_name,
        has_avatar=row.avatar_sha256 is not None,
        profile_checked_at=row.profile_checked_at,
        created_at=row.created_at,
        next_check_at=row.next_check_at,
        last_checked_at=row.last_checked_at,
        scanning=bool(row.scan_started_at and row.scan_started_at > now - LEASE),
        error=row.error,
        adapter_ready=_adapter_ready(request, row.platform),
        candidate_count=count,
    )


async def _owned(
    session: AsyncSession, request: Request, account_id: int, *, lock: bool = False
) -> ProtectedAccount:
    row = await session.get(ProtectedAccount, account_id, with_for_update=lock)
    if row is None or row.project_id != get_deps(request).rules.project:
        raise HTTPException(404, "not found")
    return row


@router.get("/protected-accounts")
async def list_accounts(
    request: Request,
    user: Reader,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ProtectedAccountPage:
    deps = get_deps(request)
    stmt = select(ProtectedAccount).where(ProtectedAccount.project_id == deps.rules.project)
    count_stmt = stmt
    if cursor is not None:
        stmt = stmt.where(ProtectedAccount.id < cursor)
    async with deps.sessions() as session:
        total = await page_total(session, count_stmt, page, cursor)
        rows = (
            await session.scalars(
                stmt.order_by(ProtectedAccount.id.desc())
                .offset(page_offset(page, limit))
                .limit(limit + 1)
            )
        ).all()
        counts = dict(
            (
                await session.execute(
                    select(AccountCandidate.protected_id, func.count())
                    .where(AccountCandidate.protected_id.in_([r.id for r in rows[:limit]]))
                    .group_by(AccountCandidate.protected_id)
                )
            ).all()
        )
    items = [_out(request, row, counts.get(row.id, 0)) for row in rows[:limit]]
    return ProtectedAccountPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit else None
    )


@router.post("/protected-accounts", status_code=201)
async def add_account(
    body: ProtectedAccountIn, request: Request, user: Writer
) -> ProtectedAccountOut:
    deps = get_deps(request)
    now = deps.clock()
    try:
        async with deps.sessions.begin() as session:
            await repo.upsert_project(session, deps.rules)
            row = ProtectedAccount(
                project_id=deps.rules.project,
                created_at=now,
                next_check_at=now,
                **body.model_dump(),
            )
            session.add(row)
            await session.flush()
            await record(
                session,
                request,
                user,
                "social_accounts.add",
                target_type="protected_account",
                target_id=row.id,
                detail=body.model_dump(),
            )
            return _out(request, row)
    except IntegrityError as exc:
        raise HTTPException(409, "account already protected") from exc


@router.put("/protected-accounts/{account_id}")
async def edit_account(
    account_id: int, body: ProtectedAccountIn, request: Request, user: Writer
) -> ProtectedAccountOut:
    deps = get_deps(request)
    async with deps.sessions.begin() as session:
        row = await _owned(session, request, account_id, lock=True)
        if (row.platform, row.handle) != (body.platform, body.handle):
            raise HTTPException(422, "platform and handle cannot be changed; create a new entry")
        for key, value in body.model_dump().items():
            setattr(row, key, value)
        # 配置修改撤销在途结果的写入资格，新配置下一轮生效。
        row.scan_started_at, row.next_check_at = None, deps.clock()
        count = await session.scalar(
            select(func.count())
            .select_from(AccountCandidate)
            .where(AccountCandidate.protected_id == account_id)
        )
        await record(
            session,
            request,
            user,
            "social_accounts.update",
            target_type="protected_account",
            target_id=row.id,
            detail=body.model_dump(),
        )
        return _out(request, row, count or 0)


@router.delete("/protected-accounts/{account_id}", status_code=204)
async def remove_account(account_id: int, request: Request, user: Writer) -> Response:
    deps = get_deps(request)
    async with deps.sessions.begin() as session:
        row = await _owned(session, request, account_id, lock=True)
        await record(
            session,
            request,
            user,
            "social_accounts.remove",
            target_type="protected_account",
            target_id=row.id,
            detail={"platform": row.platform, "handle": row.handle},
        )
        # 候选级联删除；已产生的发现与告警保留供审计。
        await session.execute(delete(ProtectedAccount).where(ProtectedAccount.id == account_id))
    return Response(status_code=204)


@router.get("/protected-accounts/{account_id}/candidates")
async def list_candidates(
    account_id: int,
    request: Request,
    user: Reader,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    order: Literal["id", "score_asc", "score_desc"] = "id",
    severity: Literal["low", "medium", "high", "critical"] | None = None,
) -> AccountCandidatePage:
    if cursor is not None and order != "id":
        raise HTTPException(422, "cursor requires order=id")
    deps = get_deps(request)
    latest = (
        select(func.max(AlertFinding.alert_id))
        .where(AlertFinding.finding_id == AccountCandidate.finding_id)
        .correlate(AccountCandidate)
        .scalar_subquery()
    )
    async with deps.sessions() as session:
        account = await _owned(session, request, account_id)
        stmt = select(AccountCandidate, latest).where(AccountCandidate.protected_id == account_id)
        if severity is not None:
            stmt = stmt.where(AccountCandidate.score >= MIN_SEVERITY[severity])
        total = await page_total(session, stmt, page, cursor)
        if cursor is not None:
            stmt = stmt.where(AccountCandidate.id > cursor)
        stmt = stmt.order_by(AccountCandidate.id)
        if order != "id":
            direction = (
                AccountCandidate.score.asc()
                if order == "score_asc"
                else AccountCandidate.score.desc()
            )
            stmt = stmt.order_by(None).order_by(direction, AccountCandidate.id)
        rows = (await session.execute(stmt.offset(page_offset(page, limit)).limit(limit + 1))).all()
    allowed = {item.casefold() for item in account.allowed_accounts}
    items = [
        AccountCandidateOut(
            id=row.id,
            platform_account_id=row.platform_account_id,
            handle=row.handle,
            display_name=row.display_name,
            profile_url=row.profile_url,
            registered_at=row.registered_at,
            score=row.score,
            severity=severity_for(row.score).value,
            signals=[k for k in ACCOUNT_SIGNALS if k in (row.signals.get("breakdown") or {})],
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            gone_at=row.gone_at,
            finding_id=row.finding_id,
            alert_id=alert_id,
            allowed=row.handle.casefold() in allowed
            or row.platform_account_id.casefold() in allowed,
        )
        for row, alert_id in rows[:limit]
    ]
    return AccountCandidatePage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit else None
    )


@router.post("/protected-accounts/{account_id}/check", status_code=202)
async def request_check(account_id: int, request: Request, user: Writer) -> Response:
    deps = get_deps(request)
    if not deps.settings.broker_url:
        raise HTTPException(503, "task queue is not configured")
    async with deps.sessions.begin() as session:
        row = await _owned(session, request, account_id, lock=True)
        if not row.enabled:
            raise HTTPException(409, "protection is disabled")
        if row.scan_started_at and row.scan_started_at > deps.clock() - LEASE:
            raise HTTPException(409, "check already running")
        row.next_check_at = deps.clock()
        await record(
            session,
            request,
            user,
            "social_accounts.check_requested",
            target_type="protected_account",
            target_id=row.id,
            detail={"platform": row.platform, "handle": row.handle},
        )
    try:
        await check_protected_account.kiq(account_id)
    except Exception as exc:
        raise HTTPException(503, "failed to queue social account check") from exc
    return Response(status_code=202)
