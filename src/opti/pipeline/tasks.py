"""Taskiq 任务。cron 按 UTC 解释（北京时间 = UTC+8）。"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from taskiq import TaskiqEvents, TaskiqState

from opti.alerting.runtime import active_ticket_client
from opti.core import policy
from opti.core.codehits import repo_value
from opti.core.secrets import require_mask_key
from opti.db import audit, repo
from opti.db.models import (
    CertificateMonitor,
    Entity,
    Finding,
    ProtectedAccount,
    Takedown,
    WatchedDomain,
)
from opti.db.partitions import drop_raw_item_partitions_before, ensure_raw_item_partitions
from opti.enrichers.tranco.enricher import TrancoIndex, refresh
from opti.exposure import service as exposure_service
from opti.gateway.dispatch import dispatch_connector_run, sweep_stale_runs
from opti.pipeline import (
    adjudication,
    campaigns,
    certificates,
    coderepos,
    evidence,
    kev,
    leakposts,
    llm_runtime,
    reports,
    retention,
    siem,
    social_accounts,
    suppression,
    watchlist,
)
from opti.pipeline.app import App, current_app, get_app, run_connector_once, set_app
from opti.pipeline.broker import broker
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.manifest import validate_instance_config
from opti.sdk.models import RawItem, raw_item_from_dict, raw_item_to_dict
from opti.sdk.registry import load_instance_config
from opti.sdk.scan import KeywordScan, scan_plan
from opti.takedown import hosting
from opti.takedown import service as takedown_service
from opti.tickets import service as tickets_service
from opti.tickets.remote import TicketRemoteError

log = logging.getLogger("opti.tasks")


@broker.task(task_name="opti.check_certificate_monitor")
async def check_certificate_monitor(monitor_id: int, force: bool = True) -> bool:
    app = await get_app()
    done = await certificates.check_monitor(app, monitor_id, force=force)
    if done:
        await dispatch_pending.kiq()
    return done


@broker.task(
    task_name="opti.check_certificates",
    schedule=[{"cron": policy.TASK_CRONS["check_certificates"]}],
)
async def check_certificates() -> int:
    app = await get_app()
    now = datetime.now(UTC)
    async with app.sessions() as session:
        ids = (
            await session.scalars(
                select(CertificateMonitor.id)
                .where(
                    CertificateMonitor.project_id == app.rules.project,
                    CertificateMonitor.enabled.is_(True),
                    CertificateMonitor.next_check_at <= now,
                    or_(
                        CertificateMonitor.scan_started_at.is_(None),
                        CertificateMonitor.scan_started_at <= now - certificates.LEASE,
                    ),
                )
                .order_by(CertificateMonitor.next_check_at)
                .limit(policy.current().batches.certificates)
            )
        ).all()
    # 每个根域名单独排队，避免一次慢检查阻塞其他根域名；租约防止重叠执行。
    for monitor_id in ids:
        await check_certificate_monitor.kiq(monitor_id, force=False)
    return len(ids)


@broker.task(task_name="opti.check_protected_account")
async def check_protected_account(account_id: int, force: bool = True) -> bool:
    app = await get_app()
    done = await social_accounts.check_account(app, account_id, force=force)
    if done:
        await dispatch_pending.kiq()
    return done


@broker.task(
    task_name="opti.check_social_accounts",
    schedule=[{"cron": policy.TASK_CRONS["check_social_accounts"]}],
)
async def check_social_accounts() -> int:
    app = await get_app()
    now = datetime.now(UTC)
    async with app.sessions() as session:
        ids = (
            await session.scalars(
                select(ProtectedAccount.id)
                .where(
                    ProtectedAccount.project_id == app.rules.project,
                    ProtectedAccount.enabled.is_(True),
                    ProtectedAccount.next_check_at <= now,
                    or_(
                        ProtectedAccount.scan_started_at.is_(None),
                        ProtectedAccount.scan_started_at <= now - social_accounts.LEASE,
                    ),
                )
                .order_by(ProtectedAccount.next_check_at)
                .limit(policy.current().batches.social_accounts)
            )
        ).all()
    # 每个受保护账号单独排队，租约防止重叠执行。
    for account_id in ids:
        await check_protected_account.kiq(account_id, force=False)
    return len(ids)


@broker.on_event(TaskiqEvents.WORKER_STARTUP)
async def _startup(_state: TaskiqState) -> None:
    require_mask_key()  # fail closed：没有遮蔽密钥时 worker 不启动


@broker.on_event(TaskiqEvents.WORKER_SHUTDOWN)
async def _shutdown(_state: TaskiqState) -> None:
    app = current_app()
    if app is not None:
        await app.close()
        set_app(None)


@broker.task(task_name="opti.ingest", retry_on_error=True)
async def ingest(item: dict[str, Any]) -> dict[str, Any]:
    app = await get_app()
    async with app.sessions() as s, s.begin():
        result = await app.processor.process(s, raw_item_from_dict(item))
    if result.alerts:
        await enrich_hosting.kiq()
        await push_tickets.kiq()
        await push_exposures.kiq()
        await dispatch_pending.kiq()
        await capture_evidence.kiq()
    return asdict(result)


async def _enqueue(item: RawItem) -> None:
    await ingest.kiq(raw_item_to_dict(item))


@broker.task(task_name="opti.run_connector")
async def run_connector(connector_id: str) -> int | None:
    app = await get_app()
    if app.jobs is not None and app.registry.manifest(connector_id).egress == "overseas":
        # remote 模式：交给境外采集节点执行，返回 run_id（上一次仍在进行时返回 None）
        async with app.sessions() as s, s.begin():
            return await dispatch_connector_run(s, app.jobs, connector_id, now=datetime.now(UTC))
    return await run_connector_once(app, connector_id, enqueue=_enqueue)


@broker.task(task_name="opti.scan_keywords")
async def scan_keywords(connector_id: str, selection: dict[str, Any]) -> int | None:
    spec = KeywordScan.model_validate(selection)
    app = await get_app()
    await app.config.refresh()
    snapshot = app.config.snapshot
    if snapshot.rules.project != spec.project_id or snapshot.version("rules") != spec.rules_version:
        log.info("规则已变化，跳过过期关键词扫描：%s v%d", spec.project_id, spec.rules_version)
        return None
    scan_plan(snapshot.rules, spec)
    if spec.scope not in app.registry.manifest(connector_id).search_inputs:
        return None
    if app.jobs is not None and app.registry.manifest(connector_id).egress == "overseas":
        async with app.sessions.begin() as s:
            return await dispatch_connector_run(
                s, app.jobs, connector_id, now=datetime.now(UTC), scan=spec, rules=snapshot.rules
            )
    return await run_connector_once(app, connector_id, enqueue=_enqueue, scan=spec)


async def _recheck_one(
    app: App, watch_id: int, *, expected_checked_at: str | None = None, force: bool = False
) -> tuple[bool, bool]:
    # 与入库路径一致：先锁 Entity，再锁 WatchedDomain。目标任务和定时任务共用此路径。
    snapshot = app.config.snapshot
    pipeline = app.pipelines.get(snapshot)
    async with app.sessions() as s, s.begin():
        now = datetime.now(UTC)
        candidate = await s.get(WatchedDomain, watch_id)
        if candidate is None or candidate.project_id != snapshot.rules.project:
            return False, False
        await repo.upsert_entity(s, "domain", candidate.domain, now)
        wd = await s.scalar(
            select(WatchedDomain)
            .where(WatchedDomain.id == watch_id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
        if (
            wd is None
            or wd.paused_by_suppression
            or (wd.expires_at and wd.expires_at <= now)
            or (not force and wd.next_check_at > now)
            or (
                force
                and (wd.last_checked_at.isoformat() if wd.last_checked_at else None)
                != expected_checked_at
            )
        ):
            return False, False

        async def on_change(
            session: AsyncSession, watched: WatchedDomain, changes: list[str]
        ) -> None:
            removed_domain = await session.scalar(
                select(Takedown.id)
                .join(Finding, Finding.id == Takedown.finding_id)
                .join(Entity, Entity.id == Finding.entity_id)
                .where(
                    Takedown.project_id == watched.project_id,
                    Takedown.domain == watched.domain,
                    Takedown.state == "removed",
                    Entity.type == "domain",
                )
                .limit(1)
            )
            if removed_domain is None:
                await pipeline.processor.on_watch_change(session, watched, changes)

        obs = await watchlist.recheck(
            s, wd, enrichment=pipeline.enrichment, on_change=on_change, now=now
        )
        # 已下架的域名复活：重新告警并关联原投诉（设计文档 12.1）
        reopened = bool(
            await takedown_service.on_recheck(s, wd, obs, now=now, enrichment=pipeline.enrichment)
        )
    return True, reopened


@broker.task(task_name="opti.recheck_watched_domain")
async def recheck_watched_domain(watch_id: int, expected_checked_at: str | None) -> bool:
    app = await get_app()
    done, reopened = await _recheck_one(
        app, watch_id, expected_checked_at=expected_checked_at, force=True
    )
    if done:
        await dispatch_pending.kiq()
    if reopened:
        await capture_evidence.kiq()
    return done


@broker.task(
    task_name="opti.recheck_watchlist", schedule=[{"cron": policy.TASK_CRONS["recheck_watchlist"]}]
)
async def recheck_watchlist(limit: int | None = None) -> int:
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.watchlist
    done = 0
    reopened = False
    # 先单独提交恢复，避免持有 WatchedDomain 锁再进入 Entity 富化。
    async with app.sessions.begin() as s:
        await suppression.restore_paused(s, now=datetime.now(UTC))
    for _ in range(limit):
        async with app.sessions() as s:
            batch = await watchlist.due(s, datetime.now(UTC), limit=1, project_id=app.rules.project)
        if not batch:
            break
        checked, revived = await _recheck_one(app, batch[0].id)
        done += int(checked)
        reopened |= revived
    if done:
        await dispatch_pending.kiq()
    if reopened:
        await capture_evidence.kiq()
    return done


# 发送失败不盖时间戳。同一条原始数据重放会被观测跳过，不再入队，因此定时重试（UTC）。
@broker.task(
    task_name="opti.dispatch_pending", schedule=[{"cron": policy.TASK_CRONS["dispatch_pending"]}]
)
async def dispatch_pending() -> int:
    app = await get_app()
    async with app.sessions() as s, s.begin():
        return await app.dispatcher.dispatch_pending(s)


@broker.task(
    task_name="opti.adjudicate_pending",
    schedule=[{"cron": policy.TASK_CRONS["adjudicate_pending"]}],
)
async def adjudicate_pending() -> int:
    app = await get_app()
    async with app.sessions() as s, s.begin():
        rt = await llm_runtime.load(s, app.keyring)  # 每轮重读：页面上改完下一轮生效
        await llm_runtime.report(s, rt, now=datetime.now(UTC))
    async with llm_runtime.adjudicator(rt) as adj:
        alerts = await adjudication.run_pending(
            app.sessions,
            adj,
            cfg=rt.cfg,
            rules=app.rules,
            organization=app.organization,
            clock=lambda: datetime.now(UTC),
        )
    if alerts:
        await dispatch_pending.kiq()
    return len(alerts)


async def _report(kind: str, month: str | None = None) -> int:
    app = await get_app()
    async with app.sessions() as s, s.begin():
        await repo.upsert_project(s, app.rules)
        row = await reports.generate(
            s, kind, project=app.rules.project, cfg=app.alerting, now=datetime.now(UTC), month=month
        )
        report_id = row.id
    async with app.sessions() as s, s.begin():
        await app.dispatcher.send_reports(s)
    return report_id


@broker.task(task_name="opti.daily_report", schedule=[{"cron": policy.TASK_CRONS["daily_report"]}])
async def daily_report() -> int:
    return await _report("daily")


@broker.task(
    task_name="opti.weekly_report", schedule=[{"cron": policy.TASK_CRONS["weekly_report"]}]
)
async def weekly_report() -> int:
    return await _report("weekly")


# 每天检查：报告时区的上一个自然月还没有月报就生成（UTC 的 1 日在部分时区仍是上月；漏跑次日补上）
@broker.task(
    task_name="opti.monthly_report", schedule=[{"cron": policy.TASK_CRONS["monthly_report"]}]
)
async def monthly_report(month: str | None = None) -> int:
    return await _report("monthly", month)


@broker.task(task_name="opti.send_reports", schedule=[{"cron": policy.TASK_CRONS["send_reports"]}])
async def send_reports() -> int:
    app = await get_app()
    async with app.sessions() as s, s.begin():
        return await app.dispatcher.send_reports(s)


@broker.task(task_name="opti.push_siem", schedule=[{"cron": policy.TASK_CRONS["push_siem"]}])
async def push_siem() -> int:
    """把达到级别的新告警推给已启用的 SIEM 渠道。"""
    app = await get_app()
    if not app.siem_senders:
        return 0
    async with app.sessions() as s, s.begin():
        return await siem.push_pending(
            s,
            app.siem_senders,
            cfg=app.sharing.siem,
            base_url=app.alerting.public_base_url,
            now=datetime.now(UTC),
        )


@broker.task(
    task_name="opti.refresh_tranco", schedule=[{"cron": policy.TASK_CRONS["refresh_tranco"]}]
)
async def refresh_tranco() -> int:
    app = await get_app()
    instance = load_instance_config(app.paths.config_dir, "tranco")
    config = validate_instance_config(app.registry.manifest("tranco"), instance.config)
    async with RateLimitedHttpClient() as http:
        return await refresh(http, TrancoIndex(Path(str(config["db_path"]))))


@broker.task(
    task_name="opti.maintain_partitions",
    schedule=[{"cron": policy.TASK_CRONS["maintain_partitions"]}],
)
async def maintain_partitions(retention_days: int | None = None) -> dict[str, list[str]]:
    app = await get_app()
    today = datetime.now(UTC).date()
    days = retention_days if retention_days is not None else app.retention.raw_items_days
    async with app.engine.begin() as conn:
        created = await ensure_raw_item_partitions(conn, today)
        dropped = await drop_raw_item_partitions_before(conn, today - timedelta(days=days))
    return {"created": created, "dropped": dropped}


@broker.task(
    task_name="opti.sweep_connector_runs",
    schedule=[{"cron": policy.TASK_CRONS["sweep_connector_runs"]}],
)
async def sweep_connector_runs() -> int:
    app = await get_app()
    async with app.sessions() as s, s.begin():
        return await sweep_stale_runs(s, datetime.now(UTC))


@broker.task(
    task_name="opti.capture_evidence", schedule=[{"cron": policy.TASK_CRONS["capture_evidence"]}]
)
async def capture_evidence(limit: int | None = None) -> int:
    """每个告警一个事务；同一轮内失败的告警不再重试，间隔到下一轮（最多 3 次）。"""
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.evidence
    done = 0
    seen: list[int] = []
    for _ in range(limit):
        async with app.sessions() as s, s.begin():
            alert = await evidence.next_pending(s, exclude=seen)
            if alert is None:
                break
            seen.append(alert.id)
            if await evidence.capture(
                s, alert, app.enrichment, datetime.now(UTC), takedown=app.takedown
            ):
                done += 1
    return done


@broker.task(
    task_name="opti.enrich_hosting", schedule=[{"cron": policy.TASK_CRONS["enrich_hosting"]}]
)
async def enrich_hosting(limit: int | None = None) -> int:
    """为高危告警预取托管信息（设计文档 12.1），投诉对象清单只读缓存。每个实体一个事务。"""
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.hosting
    async with app.sessions() as s:
        ids = await hosting.pending_entity_ids(s, datetime.now(UTC), limit=limit)
    done = 0
    for entity_id in ids:
        async with app.sessions() as s, s.begin():
            entity = await s.get(Entity, entity_id)
            if entity is not None:
                await hosting.prefetch(s, app.enrichment, entity, datetime.now(UTC))
                done += 1
    return done


@broker.task(
    task_name="opti.takedown_reminders",
    schedule=[{"cron": policy.TASK_CRONS["takedown_reminders"]}],
)
async def takedown_reminders(limit: int | None = None) -> int:
    """下架投诉超过 SLA 未处理：提醒并给出升级渠道（设计文档 12.1）。渠道全部失败时不记提醒，下次重试。"""
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.reminders
    sent = 0
    async with app.sessions() as s, s.begin():
        now = datetime.now(UTC)
        for td in await takedown_service.overdue(s, now, limit=limit):
            notice = takedown_service.reminder_notice(
                app.takedown, td, app.alerting.public_base_url
            )
            if await app.dispatcher.send_notice(notice):
                await takedown_service.mark_reminded(s, td, app.takedown, now)
                sent += 1
    return sent


def _push_error(e: Exception) -> str:
    return e.public_message() if isinstance(e, TicketRemoteError) else type(e).__name__


@broker.task(task_name="opti.push_tickets", schedule=[{"cron": policy.TASK_CRONS["push_tickets"]}])
async def push_tickets(limit: int | None = None) -> int:
    """按 config/tickets.yaml 的 auto_push 自动推送新告警（设计文档 D8）。每个告警一个事务；失败的下一轮重试。"""
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.tickets
    client = active_ticket_client(app.tickets)
    if client is None or not app.tickets_cfg.auto_push:
        return 0
    done = 0
    seen: list[int] = []
    for _ in range(limit):
        async with app.sessions() as s, s.begin():
            now = datetime.now(UTC)
            alert = await tickets_service.next_auto_push(s, app.tickets_cfg, now, exclude=seen)
            if alert is None:
                break
            seen.append(alert.id)
            try:
                result = await tickets_service.push(
                    s, client, alert, base_url=app.alerting.public_base_url, now=now
                )
            except Exception as e:  # 工单系统故障不能影响其他告警
                log.warning("告警 %s 自动推送工单失败：%s", alert.id, _push_error(e))
                continue
            await audit.append(
                s, actor="system", action="ticket.push", now=now, target_type="alert",
                target_id=str(alert.id), detail={"channel": result.channel, "ticket_ref": result.ref, "auto": True},
            )  # fmt: skip
            done += 1
    return done


@broker.task(
    task_name="opti.push_exposures", schedule=[{"cron": policy.TASK_CRONS["push_exposures"]}]
)
async def push_exposures(limit: int | None = None) -> int:
    """凭据暴露：按 config/tickets.yaml 的 auto_push 把待推送的受影响账户推给 IT（设计文档 2.3）。"""
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.exposures
    client = active_ticket_client(app.tickets)
    if client is None or not app.tickets_cfg.auto_push:
        return 0
    done = 0
    seen: list[int] = []
    for _ in range(limit):
        async with app.sessions() as s, s.begin():
            now = datetime.now(UTC)
            row = await exposure_service.next_auto_push(s, app.tickets_cfg, now, exclude=seen)
            if row is None:
                break
            alert, finding = row
            seen.append(alert.id)
            try:
                count, result = await exposure_service.push(
                    s, client, alert, finding, base_url=app.alerting.public_base_url, now=now
                )
            except Exception as e:  # 工单系统故障：账户保持待推送，下一轮重试
                log.warning("告警 %s 的受影响账户推送失败：%s", alert.id, _push_error(e))
                continue
            await audit.append(
                s, actor="system", action="exposure.push", now=now, target_type="alert", target_id=str(alert.id),
                detail={"count": count, "channel": result.channel, "ticket_ref": result.ref, "auto": True},
            )  # fmt: skip
            done += 1
    return done


@broker.task(
    task_name="opti.recompute_campaigns",
    schedule=[{"cron": policy.TASK_CRONS["recompute_campaigns"]}],
)
async def recompute_campaigns() -> dict[str, int]:
    """按共享独占基础设施重算仿冒活动候选，并为已确认活动追加待确认成员（设计文档 8）。"""
    app = await get_app()
    await app.config.refresh()
    async with app.sessions() as s, s.begin():
        await repo.upsert_project(s, app.rules)
        result = await campaigns.recompute(
            s, app.rules.project, app.campaigns, now=datetime.now(UTC)
        )
    return asdict(result)


@broker.task(
    task_name="opti.apply_retention", schedule=[{"cron": policy.TASK_CRONS["apply_retention"]}]
)
async def apply_retention() -> dict[str, int]:
    """Clear expired database rows in one transaction, then remove evidence objects."""
    app = await get_app()
    now = datetime.now(UTC)
    async with app.sessions() as s, s.begin():
        result = await retention.apply(s, app.retention, now=now)
        await audit.append(
            s, actor="system:retention", action="retention.purge", now=now, detail=result.counts
        )
    return {
        **result.counts,
        "evidence_files": await retention.delete_objects(app.store, result.objects),
    }


@broker.task(
    task_name="opti.rematch_leak_posts",
    schedule=[{"cron": policy.TASK_CRONS["rematch_leak_posts"]}],
)
async def rematch_leak_posts(days: int | None = None) -> int:
    """Rematch the last year of posts against the current vendor inventory."""
    app = await get_app()
    days = days if days is not None else policy.current().scanning.leak_rematch_days
    try:
        await app.config.refresh()
        async with app.sessions() as s, s.begin():
            await repo.upsert_project(s, app.rules)
            alerts = await leakposts.rematch(s, app.processor, now=datetime.now(UTC), days=days)
    except Exception as exc:
        await _record_rematch(app, "vendors", error=type(exc).__name__)
        raise
    await _record_rematch(app, "vendors", alerts=len(alerts))
    if alerts:
        await dispatch_pending.kiq()
    return len(alerts)


@broker.task(
    task_name="opti.scan_code_repos", schedule=[{"cron": policy.TASK_CRONS["scan_code_repos"]}]
)
async def scan_code_repos(limit: int | None = None) -> int:
    """Scan due public repositories; overseas enrichers run on collectors in remote mode."""
    app = await get_app()
    limit = limit if limit is not None else policy.current().batches.code_repos
    if app.enrichment.get("secret_scan") is None:
        return 0
    done = 0
    opened = False
    for _ in range(limit):
        async with app.sessions() as session, session.begin():
            now = datetime.now(UTC)
            rows = await coderepos.due(session, now, limit=1, project_id=app.rules.project)
            if not rows:
                break
            row = rows[0]
            entity = await repo.upsert_entity(session, "repo", repo_value(row.repo), now)
            data = (await app.enrichment.enrich(entity, coderepos.CODE_ENRICHERS, force=True)).get(
                "secret_scan"
            )
            data = data or {"scanned": False, "error": "unavailable"}
            coderepos.record_scan(row, data, now)
            opened |= bool(await app.processor.on_repo_scanned(session, row.repo, data, now))
        done += 1
    if opened:
        await dispatch_pending.kiq()
    return done


@broker.task(task_name="opti.rematch_kev", schedule=[{"cron": policy.TASK_CRONS["rematch_kev"]}])
async def rematch_kev() -> int:
    """Rematch the local software inventory against all stored KEV entries."""
    app = await get_app()
    try:
        await app.config.refresh()
        async with app.sessions() as s, s.begin():
            await repo.upsert_project(s, app.rules)
            alerts = await kev.rematch(s, app.processor, now=datetime.now(UTC))
    except Exception as exc:
        await _record_rematch(app, "software", error=type(exc).__name__)
        raise
    await _record_rematch(app, "software", alerts=len(alerts))
    if alerts:
        await dispatch_pending.kiq()
    return len(alerts)


async def _record_rematch(
    app: App, kind: str, *, alerts: int | None = None, error: str | None = None
) -> None:
    detail: dict[str, Any] = {"kind": kind, "version": app.config.snapshot.version(kind)}
    detail.update({"alerts": alerts} if error is None else {"error": error})
    async with app.sessions() as session, session.begin():
        await audit.append(
            session,
            actor="system:rematch",
            action="config.rematched",
            now=datetime.now(UTC),
            target_type="config",
            target_id=kind,
            detail=detail,
        )
