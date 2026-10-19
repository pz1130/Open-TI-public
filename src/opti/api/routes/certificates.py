"""自有域名证书到期监控管理，独立权限及审计。"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, StrictBool, StrictInt, model_validator
from sqlalchemy import case, delete, func, select, update
from sqlalchemy.exc import IntegrityError

from opti.api.deps import Principal, get_deps, record, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.core.certificates import certificate_domain, certificate_expiry, in_scope, retired
from opti.db import repo
from opti.db.models import (
    Alert,
    AlertFinding,
    CertificateMonitor,
    Entity,
    Finding,
    MonitoredCertificate,
)
from opti.pipeline.certificates import LEASE
from opti.pipeline.tasks import check_certificate_monitor

router = APIRouter(tags=["certificates"])
log = logging.getLogger("opti.certificates")
Reader = Annotated[Principal, Depends(require(Perm.CERTIFICATES_READ))]
Writer = Annotated[Principal, Depends(require(Perm.CERTIFICATES_WRITE))]
Approver = Annotated[Principal, Depends(require(Perm.CERTIFICATES_APPROVE))]


class CertificateMonitorIn(BaseModel):
    root_domain: str = Field(min_length=3, max_length=253)
    warn_days: StrictInt = Field(default=30, ge=1, le=365)
    enabled: StrictBool = True
    known_domains: list[str] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def domains(self) -> CertificateMonitorIn:
        self.root_domain = certificate_domain(self.root_domain)
        self.known_domains = sorted({certificate_domain(d) for d in self.known_domains})
        if any(not in_scope(d, self.root_domain) for d in self.known_domains):
            raise ValueError("补充的子域名必须属于所填根域名")
        return self


class CertificateMonitorOut(BaseModel):
    id: int
    root_domain: str
    enabled: bool
    warn_days: int
    known_domains: list[str]
    created_at: datetime
    next_check_at: datetime
    last_checked_at: datetime | None
    scanning: bool
    error: str | None
    truncated: bool
    host_count: int


class CertificateMonitorPage(BaseModel):
    items: list[CertificateMonitorOut]
    next_cursor: int | None
    total: int = 0


class MonitoredCertificateOut(BaseModel):
    id: int
    domain: str
    state: str
    checked_at: datetime | None
    certificate_checked_at: datetime | None
    not_after: datetime | None
    days_remaining: int | None
    issuer: str | None
    error: str | None
    approved: bool
    approved_at: datetime | None
    warn_days: int | None
    effective_warn_days: int


class CertificateHostConfig(BaseModel):
    approved: StrictBool
    warn_days: StrictInt | None = Field(default=None, ge=1, le=365)


class MonitoredCertificatePage(BaseModel):
    items: list[MonitoredCertificateOut]
    next_cursor: int | None
    total: int = 0


def _official(root: str, official: Iterable[str]) -> bool:
    """只监控本机构的域名：根域名须是规则中的官方域名或其子域名。"""
    for raw in official:
        try:
            domain = certificate_domain(raw)
        except ValueError:
            continue
        if in_scope(root, domain):
            return True
    return False


def _out(row: CertificateMonitor, now: datetime, count: int = 0) -> CertificateMonitorOut:
    return CertificateMonitorOut(
        id=row.id,
        root_domain=row.root_domain,
        enabled=row.enabled,
        warn_days=row.warn_days,
        known_domains=row.known_domains,
        created_at=row.created_at,
        next_check_at=row.next_check_at,
        last_checked_at=row.last_checked_at,
        scanning=bool(row.scan_started_at and row.scan_started_at > now - LEASE),
        error=row.error,
        truncated=row.truncated,
        host_count=count,
    )


@router.get("/certificate-monitors")
async def list_monitors(
    request: Request,
    user: Reader,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CertificateMonitorPage:
    deps = get_deps(request)
    stmt = select(CertificateMonitor).where(CertificateMonitor.project_id == deps.rules.project)
    count_stmt = stmt
    if cursor is not None:
        stmt = stmt.where(CertificateMonitor.id < cursor)
    async with deps.sessions() as session:
        total = await page_total(session, count_stmt, page, cursor)
        rows = (
            await session.scalars(
                stmt.order_by(CertificateMonitor.id.desc())
                .offset(page_offset(page, limit))
                .limit(limit + 1)
            )
        ).all()
        counts = dict(
            (
                await session.execute(
                    select(MonitoredCertificate.monitor_id, func.count())
                    .where(MonitoredCertificate.monitor_id.in_([r.id for r in rows[:limit]]))
                    .group_by(MonitoredCertificate.monitor_id)
                )
            ).all()
        )
    items = [_out(row, deps.clock(), counts.get(row.id, 0)) for row in rows[:limit]]
    return CertificateMonitorPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit else None
    )


@router.post("/certificate-monitors", status_code=201)
async def add_monitor(
    body: CertificateMonitorIn, request: Request, user: Writer
) -> CertificateMonitorOut:
    deps = get_deps(request)
    now = deps.clock()
    if not _official(body.root_domain, deps.rules.domains.official):
        raise HTTPException(
            422, "root domain must be one of the official domains or their subdomains"
        )
    try:
        async with deps.sessions.begin() as session:
            await repo.upsert_project(session, deps.rules)
            row = CertificateMonitor(
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
                "certificates.add",
                target_type="certificate_monitor",
                target_id=row.id,
                detail=body.model_dump(),
            )
            result = _out(row, now)
    except IntegrityError as exc:
        raise HTTPException(409, "domain already monitored") from exc
    if result.enabled and deps.settings.broker_url:
        try:
            await check_certificate_monitor.kiq(result.id)
        except Exception as exc:
            # 记录已提交，定时调度会重试，不因队列短暂故障让用户重复添加根域名。
            log.warning("首次证书扫描入队失败：%s", type(exc).__name__)
    return result


@router.put("/certificate-monitors/{monitor_id}")
async def edit_monitor(
    monitor_id: int, body: CertificateMonitorIn, request: Request, user: Writer
) -> CertificateMonitorOut:
    deps = get_deps(request)
    async with deps.sessions.begin() as session:
        row = await session.get(CertificateMonitor, monitor_id, with_for_update=True)
        if row is None or row.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        if row.root_domain != body.root_domain:
            raise HTTPException(422, "root domain cannot be changed; create a new monitor")
        for key, value in body.model_dump().items():
            setattr(row, key, value)
        # 配置修改撤销在途结果的写入资格，新配置下一轮生效。
        row.scan_started_at, row.next_check_at = None, deps.clock()
        count = await session.scalar(
            select(func.count())
            .select_from(MonitoredCertificate)
            .where(MonitoredCertificate.monitor_id == monitor_id)
        )
        await record(
            session,
            request,
            user,
            "certificates.update",
            target_type="certificate_monitor",
            target_id=row.id,
            detail=body.model_dump(),
        )
        return _out(row, deps.clock(), count or 0)


@router.delete("/certificate-monitors/{monitor_id}", status_code=204)
async def remove_monitor(monitor_id: int, request: Request, user: Writer) -> Response:
    deps = get_deps(request)
    async with deps.sessions.begin() as session:
        row = await session.get(CertificateMonitor, monitor_id, with_for_update=True)
        if row is None or row.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        await record(
            session,
            request,
            user,
            "certificates.remove",
            target_type="certificate_monitor",
            target_id=row.id,
            detail={"root_domain": row.root_domain},
        )
        await session.execute(delete(CertificateMonitor).where(CertificateMonitor.id == monitor_id))
    return Response(status_code=204)


@router.get("/certificate-monitors/{monitor_id}/hosts")
async def list_hosts(
    monitor_id: int,
    request: Request,
    user: Reader,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    q: Annotated[str | None, Query(max_length=253)] = None,
    order: Literal["id", "expiry_asc", "expiry_desc"] = "id",
    approval: Literal["all", "pending", "approved"] = "all",
) -> MonitoredCertificatePage:
    if cursor is not None and order != "id":
        raise HTTPException(422, "cursor requires order=id")
    deps = get_deps(request)
    async with deps.sessions() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        if monitor is None or monitor.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        stmt = select(MonitoredCertificate).where(MonitoredCertificate.monitor_id == monitor_id)
        if approval != "all":
            stmt = stmt.where(
                MonitoredCertificate.approved_at.is_(None)
                if approval == "pending"
                else MonitoredCertificate.approved_at.is_not(None)
            )
        if q:
            stmt = stmt.where(
                MonitoredCertificate.domain.contains(q.strip().lower(), autoescape=True)
            )
        total = await page_total(session, stmt, page, cursor)
        if cursor is not None:
            stmt = stmt.where(MonitoredCertificate.id > cursor)
        expiry = case((MonitoredCertificate.state != "error", MonitoredCertificate.not_after))
        stmt = stmt.order_by(MonitoredCertificate.id)
        if order != "id":
            direction = expiry.asc() if order == "expiry_asc" else expiry.desc()
            stmt = stmt.order_by(None).order_by(direction.nulls_last(), MonitoredCertificate.id)
        rows = (await session.scalars(stmt.offset(page_offset(page, limit)).limit(limit + 1))).all()
    now = deps.clock()
    items = []
    for row in rows[:limit]:
        state = (
            certificate_expiry(row.certificate, now, row.warn_days or monitor.warn_days)[0]
            if row.state != "error" and row.certificate
            else row.state
        )
        if row.approved_at is None and retired(
            row.domain, row.failing_since, monitor.root_domain, monitor.known_domains, now
        ):
            state = "retired"  # 连续失败满 30 天，不再检查
        days = (
            math.floor((row.not_after - now).total_seconds() / 86400)
            if row.not_after and state != "error"
            else None
        )
        items.append(
            MonitoredCertificateOut(
                id=row.id,
                domain=row.domain,
                state=state,
                checked_at=row.checked_at,
                certificate_checked_at=row.certificate_checked_at,
                not_after=row.not_after,
                days_remaining=days,
                issuer=row.certificate.get("issuer_o") or row.certificate.get("issuer_cn"),
                error=row.error,
                approved=row.approved_at is not None,
                approved_at=row.approved_at,
                warn_days=row.warn_days,
                effective_warn_days=row.warn_days or monitor.warn_days,
            )
        )
    return MonitoredCertificatePage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit else None
    )


@router.put("/certificate-monitors/{monitor_id}/hosts/{host_id}", status_code=204)
async def configure_host(
    monitor_id: int,
    host_id: int,
    body: CertificateHostConfig,
    request: Request,
    user: Approver,
) -> Response:
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id, with_for_update=True)
        if monitor is None or monitor.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        row = await session.get(MonitoredCertificate, host_id, with_for_update=True)
        if row is None or row.monitor_id != monitor_id:
            raise HTTPException(404, "not found")
        before = {"approved": row.approved_at is not None, "warn_days": row.warn_days}
        if body.approved:
            if row.approved_at is None:
                row.approved_at, row.approved_by = now, user.user_id
            row.failing_since = None  # 管理员确认也重新启用已停查主机
        else:
            row.approved_at, row.approved_by = None, None
            # 撤销确认后停止尚未发送的提醒，保留历史。
            ids = (
                select(Finding.id)
                .join(Entity, Entity.id == Finding.entity_id)
                .where(
                    Finding.project_id == monitor.project_id,
                    Finding.category == "certificate_expiry",
                    Entity.type == "tls_endpoint",
                    Entity.value == f"{row.domain}@{monitor.id}",
                )
            )
            alerts = select(AlertFinding.alert_id).where(AlertFinding.finding_id.in_(ids))
            await session.execute(
                update(Alert)
                .where(
                    Alert.id.in_(alerts),
                    Alert.status.in_(("open", "acknowledged")),
                )
                .values(status="closed", closed_at=now, updated_at=now)
            )
            await session.execute(
                update(Finding)
                .where(Finding.id.in_(ids))
                .values(
                    match=Finding.match.op("-")("certificate_alert_key"),
                )
            )
        row.warn_days = body.warn_days
        monitor.next_check_at = now
        await record(
            session,
            request,
            user,
            "certificates.host_configured",
            target_type="monitored_certificate",
            target_id=row.id,
            detail={"domain": row.domain, "before": before, "after": body.model_dump()},
        )
    return Response(status_code=204)


@router.post("/certificate-monitors/{monitor_id}/check", status_code=202)
async def request_check(monitor_id: int, request: Request, user: Writer) -> Response:
    deps = get_deps(request)
    if not deps.settings.broker_url:
        raise HTTPException(503, "task queue is not configured")
    async with deps.sessions.begin() as session:
        row = await session.get(CertificateMonitor, monitor_id, with_for_update=True)
        if row is None or row.project_id != deps.rules.project:
            raise HTTPException(404, "not found")
        if not row.enabled:
            raise HTTPException(409, "monitor is disabled")
        if row.scan_started_at and row.scan_started_at > deps.clock() - LEASE:
            raise HTTPException(409, "check already running")
        row.next_check_at = deps.clock()
        await record(
            session,
            request,
            user,
            "certificates.check_requested",
            target_type="certificate_monitor",
            target_id=row.id,
            detail={"root_domain": row.root_domain},
        )
    try:
        await check_certificate_monitor.kiq(monitor_id)
    except Exception as exc:
        raise HTTPException(503, "failed to queue certificate check") from exc
    return Response(status_code=202)
