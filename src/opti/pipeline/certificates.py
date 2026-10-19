"""证书到期检查：领取短租约，网络请求在事务外执行，再原子保存状态和告警。"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.core.certificates import certificate_domain, certificate_expiry, in_scope, retired
from opti.core.scoring import Category, Score, severity_for
from opti.db import repo
from opti.db.models import Alert, AlertFinding, CertificateMonitor, Finding, MonitoredCertificate
from opti.sdk.base import Enricher

if TYPE_CHECKING:
    from opti.pipeline.app import App

LEASE = timedelta(minutes=15)


@dataclass(frozen=True)
class Scan:
    id: int
    project_id: str
    root: str
    warn_days: int
    domains: tuple[str, ...]
    started: datetime
    retired: frozenset[str] = frozenset()  # 连续失败满 30 天的已发现主机，CT 再返回也不检查


async def _call(enricher: Enricher | None, domain: str) -> dict[str, Any]:
    if enricher is None:
        return {"error": "enricher_disabled"}
    try:
        return await asyncio.wait_for(enricher.enrich("domain", domain), timeout=120)
    except Exception as exc:
        return {"error": type(exc).__name__}


async def collect(
    scan: Scan, discovery: Enricher | None, tls: Enricher | None
) -> tuple[dict[str, dict[str, Any]], str | None, bool, bool]:
    """返回（各主机结果、问题摘要、是否超出数量上限、发现是否失败）。"""
    discovered = await _call(discovery, scan.root)
    hosts = set(scan.domains) | {scan.root}
    for raw in discovered.get("domains", []):
        if not isinstance(raw, str):
            continue
        try:
            host = certificate_domain(raw)
        except ValueError:
            continue
        if in_scope(host, scan.root) and host not in scan.retired:
            hosts.add(host)
    truncated = (
        bool(discovered.get("truncated")) or len(hosts) > policy.current().certificates.max_hosts
    )
    # 根域名和人工补充/之前发现的域名优先，超出上限在页面明确提示。
    ordered = list(dict.fromkeys([scan.root, *scan.domains, *sorted(hosts)]))[
        : policy.current().certificates.max_hosts
    ]
    semaphore = asyncio.Semaphore(10)
    results: dict[str, dict[str, Any]] = {}

    async def check(host: str) -> None:
        async with semaphore:
            results[host] = await _call(tls, host)

    jobs = [asyncio.create_task(check(host)) for host in ordered]
    try:
        await asyncio.wait_for(
            asyncio.gather(*jobs),
            timeout=policy.current().certificates.scan_timeout_seconds,
        )
    except TimeoutError:
        for host in ordered:
            results.setdefault(host, {"error": "scan_timeout"})
    finally:
        for job in jobs:
            if not job.done():
                job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
    discovery_failed = bool(discovered.get("error"))
    problem = str(discovered["error"]) if discovery_failed else None
    failures = sum(
        certificate_expiry(data, datetime.now(UTC), scan.warn_days)[0] == "error"
        for data in results.values()
    )
    if failures:
        problem = "; ".join(filter(None, [problem, f"tls_failed:{failures}"]))
    return results, problem, truncated, discovery_failed


async def _alert(
    session: AsyncSession, scan: Scan, host: str, data: dict[str, Any], now: datetime
) -> None:
    state, end, days, value = certificate_expiry(data, now, scan.warn_days)
    if state == "error":
        return  # 网络故障不能冒充证书恢复，也不能清除去重记录。
    # 独立的 TLS 端点实体，避免覆盖同域名已有的仿冒/未经批准证书发现。
    entity = await repo.upsert_entity(session, "tls_endpoint", f"{host}@{scan.id}", now)
    previous = await session.scalar(
        select(Finding)
        .where(Finding.project_id == scan.project_id, Finding.entity_id == entity.id)
        .with_for_update()
    )
    severity = severity_for(value)
    key = (
        f"{data.get('sha256', '')}:{end.isoformat() if end else ''}:{severity.value}"
        if value
        else None
    )
    # 同一主机可能属于已删除后重建的监控或嵌套的根域名：按主机取最近一次的提醒记录去重
    same_host = (
        Finding.project_id == scan.project_id,
        Finding.category == Category.CERTIFICATE_EXPIRY.value,
        Finding.match["domain"].astext == host,
    )
    latest = await session.scalar(
        select(Finding).where(*same_host).order_by(Finding.last_seen.desc()).limit(1)
    )
    old_key = latest.match.get("certificate_alert_key") if latest is not None else None
    entity.enrichment = {"tls": {"data": data, "fetched_at": now.isoformat()}}
    if not value and previous is None:
        return
    reason = f"{host} 证书{'已过期' if state == 'expired' else '即将到期'}：到期 {end.isoformat() if end else ''}，剩余 {days} 天"
    up = await repo.upsert_finding(
        session,
        project_id=scan.project_id,
        entity=entity,
        score=Score(value, severity, Category.CERTIFICATE_EXPIRY, {"certificate_expiry": value}),
        match={
            "domain": host,
            "root_domain": scan.root,
            "certificate": data,
            "certificate_alert_key": key,
            "reasons": [{"reason": reason}] if value else [],
        },
        source="certificate_monitor",
        now=now,
    )
    if value and key != old_key:
        await repo.open_alert(session, up.finding, severity, now)
    elif not value:
        # 证书恢复：关闭这台主机所有未结的到期告警（含已删除监控留下的）
        ids = (
            select(AlertFinding.alert_id)
            .join(Finding, Finding.id == AlertFinding.finding_id)
            .where(*same_host)
        )
        await session.execute(
            update(Alert)
            .where(Alert.id.in_(ids), Alert.status.in_(("open", "acknowledged")))
            .values(status="closed", closed_at=now, updated_at=now)
        )


async def check_monitor(app: App, monitor_id: int, *, force: bool = False) -> bool:
    started = datetime.now(UTC)
    async with app.sessions.begin() as session:
        monitor = await session.scalar(
            select(CertificateMonitor)
            .where(
                CertificateMonitor.id == monitor_id,
                CertificateMonitor.project_id == app.rules.project,
            )
            .with_for_update(skip_locked=True)
        )
        if (
            monitor is None
            or not monitor.enabled
            or (monitor.scan_started_at and monitor.scan_started_at > started - LEASE)
            or (not force and monitor.next_check_at > started)
        ):
            return False
        rows = (
            await session.scalars(
                select(MonitoredCertificate)
                .where(MonitoredCertificate.monitor_id == monitor.id)
                .order_by(MonitoredCertificate.domain)
            )
        ).all()
        gone = {
            row.domain
            for row in rows
            if row.approved_at is None
            and retired(
                row.domain, row.failing_since, monitor.root_domain, monitor.known_domains, started
            )
        }
        previous = [row.domain for row in rows if row.domain not in gone]
        unfinished = [
            row.domain for row in rows if row.domain not in gone and row.error == "scan_timeout"
        ]
        approved = [row.domain for row in rows if row.approved_at is not None]
        scan = Scan(
            monitor.id,
            monitor.project_id,
            monitor.root_domain,
            monitor.warn_days,
            tuple(dict.fromkeys([*approved, *unfinished, *monitor.known_domains, *previous])),
            started,
            frozenset(gone),
        )
        monitor.scan_started_at = started

    results, problem, truncated, discovery_failed = await collect(
        scan, app.enrichment.get("subdomains"), app.enrichment.get("tls")
    )
    now = datetime.now(UTC)
    async with app.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id, with_for_update=True)
        # 停用、修改或删除期间不落旧结果；崩溃的检查租约最多 15 分钟后可重领。
        if monitor is None or not monitor.enabled or monitor.scan_started_at != scan.started:
            return False
        existing = {
            row.domain: row
            for row in (
                await session.scalars(
                    select(MonitoredCertificate).where(
                        MonitoredCertificate.monitor_id == monitor_id
                    )
                )
            ).all()
        }
        for host, data in sorted(results.items()):
            row = existing.get(host)
            if row is None:
                row = MonitoredCertificate(monitor_id=monitor_id, domain=host)
                session.add(row)
            host_scan = replace(scan, warn_days=row.warn_days or scan.warn_days)
            state, end, _days, _score = certificate_expiry(data, now, host_scan.warn_days)
            row.state, row.checked_at = state, now
            row.error = (
                str(data.get("error") or "certificate_unavailable") if state == "error" else None
            )
            if state != "error":
                row.certificate, row.not_after, row.certificate_checked_at = data, end, now
                row.failing_since = None
            elif row.failing_since is None:
                row.failing_since = now
            if row.approved_at is not None:
                await _alert(session, host_scan, host, data, now)
        monitor.last_checked_at = now
        # 发现失败或检查超时才约一小时后重试；个别主机连不上（常是已下线的历史主机）照常按天检查
        timed_out = any(data.get("error") == "scan_timeout" for data in results.values())
        monitor.next_check_at = now + timedelta(
            hours=policy.current().certificates.retry_hours
            if discovery_failed or timed_out
            else policy.current().certificates.interval_hours
        )
        monitor.scan_started_at = None
        monitor.error, monitor.truncated = problem, truncated
    return True
