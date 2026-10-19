"""保留期清理（设计文档 2.5）：期限集中配置，审计日志不自动删除。"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import and_, delete, exists, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.db.models import (
    AccountCandidate,
    Adjudication,
    Alert,
    AlertFinding,
    CampaignMember,
    ConnectorRun,
    Document,
    Evidence,
    ExposedAccount,
    Feedback,
    Finding,
    FindingObservation,
    Report,
    SuppressionRule,
    Takedown,
    TakedownEvent,
)
from opti.db.partitions import drop_raw_item_partitions_before
from opti.exposure import service as exposure_service
from opti.pipeline import documents
from opti.storage.objects import ObjectStore
from opti.takedown.service import ACTIVE_STATES

BATCH = 5000
ACTIVE_ALERTS = ("open", "acknowledged")
SOCIAL_CANDIDATE_DAYS = 90  # 冒充社交账号候选：久未再见且从未关联告警的删除（固定，不随网页配置）
log = logging.getLogger("opti.retention")


async def purge_report_contacts(session: AsyncSession, before: datetime) -> int:
    findings = await session.execute(
        text(
            "UPDATE finding SET match = jsonb_set(match, '{context,contact}', 'null'::jsonb) "
            "WHERE match->'context'->>'contact' IS NOT NULL AND first_seen < :before RETURNING id"
        ),
        {"before": before},
    )
    await session.execute(
        text(
            "UPDATE raw_item SET payload = jsonb_set(payload, '{context,contact}', 'null'::jsonb) "
            "WHERE connector_id = 'public_report' AND payload->'context'->>'contact' IS NOT NULL "
            "AND fetched_at < :before"
        ),
        {"before": before},
    )
    return len(findings.all())


class RetentionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    raw_items_days: int = Field(default=90, ge=7)
    report_contacts_days: int = Field(default=90, ge=0)
    exposed_accounts_days: int = Field(default=180, ge=1)
    documents_days: int = Field(default=365, ge=1)
    findings_days: int = Field(default=365, ge=30)
    cases_days: int = Field(default=1095, ge=30)
    connector_runs_days: int = Field(default=90, ge=7)
    reports_days: int = Field(default=365, ge=30)

    @model_validator(mode="after")
    def _cases_outlive_findings(self) -> RetentionConfig:
        if self.cases_days < self.findings_days:
            raise ValueError("cases_days 不能短于 findings_days")
        return self


def load_retention_config(path: Path) -> RetentionConfig:
    if not path.exists():
        return RetentionConfig()
    return RetentionConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


@dataclass
class PurgeResult:
    counts: dict[str, int]
    objects: list[tuple[str, str | None]] = field(
        default_factory=list
    )  # 待删除的证据文件（键、版本）


def _candidates(findings_before: datetime, cases_before: datetime) -> Any:
    has_alert = exists().where(AlertFinding.finding_id == Finding.id)
    active_alert = exists().where(
        AlertFinding.finding_id == Finding.id,
        AlertFinding.alert_id == Alert.id,
        Alert.status.in_(ACTIVE_ALERTS),
    )
    busy_takedown = exists().where(
        Takedown.finding_id == Finding.id,
        or_(Takedown.state.in_(ACTIVE_STATES), Takedown.resolved_at >= cases_before),
    )
    return (
        select(Finding.id)
        .where(
            or_(
                and_(~has_alert, Finding.last_seen < findings_before),
                and_(has_alert, Finding.last_seen < cases_before, ~active_alert, ~busy_takedown),
            )
        )
        .order_by(Finding.id)
    )


async def eligible_findings(
    session: AsyncSession,
    *,
    findings_before: datetime,
    cases_before: datetime,
    limit: int | None,
) -> list[int]:
    """清理与预览共用筛选，避免确认的数量和下一轮实际删除不一致。"""
    query = _candidates(findings_before, cases_before)
    if limit is not None:
        query = query.limit(limit)
    ids = list((await session.scalars(query)).all())
    # A grouped alert may still refer to a newer finding. Keep the entire group
    # until every finding is eligible so the active case and its evidence survive.
    candidate_alerts = (
        list(
            (
                await session.scalars(
                    select(AlertFinding.alert_id).where(AlertFinding.finding_id.in_(ids))
                )
            ).all()
        )
        if ids
        else []
    )
    if candidate_alerts:
        shared_alerts = set(
            (
                await session.scalars(
                    select(AlertFinding.alert_id).where(
                        AlertFinding.alert_id.in_(candidate_alerts),
                        AlertFinding.finding_id.not_in(ids),
                    )
                )
            ).all()
        )
        if shared_alerts:
            blocked = set(
                (
                    await session.scalars(
                        select(AlertFinding.finding_id).where(
                            AlertFinding.alert_id.in_(shared_alerts)
                        )
                    )
                ).all()
            )
            ids = [finding_id for finding_id in ids if finding_id not in blocked]
    return ids


async def purge_findings(
    session: AsyncSession, *, findings_before: datetime, cases_before: datetime
) -> PurgeResult:
    """删除到期的发现：没有告警的按 findings 期限；有告警的（案件）按 cases 期限，且不能有未结告警或进行中的下架。"""
    ids = await eligible_findings(
        session,
        findings_before=findings_before,
        cases_before=cases_before,
        limit=policy.current().batches.retention,
    )
    counts = {"findings": len(ids), "alerts": 0, "evidence": 0, "takedowns": 0}
    if not ids:
        return PurgeResult(counts)
    alert_ids = list(
        (
            await session.scalars(
                select(AlertFinding.alert_id).where(AlertFinding.finding_id.in_(ids))
            )
        ).all()
    )
    takedown_ids = list(
        (
            await session.scalars(
                select(Takedown.id).where(
                    or_(Takedown.finding_id.in_(ids), Takedown.alert_id.in_(alert_ids))
                )
            )
        ).all()
    )
    evidence = (
        await session.execute(
            delete(Evidence)
            .where(or_(Evidence.finding_id.in_(ids), Evidence.alert_id.in_(alert_ids)))
            .returning(Evidence.object_key, Evidence.version_id)
        )
    ).all()
    await session.execute(delete(TakedownEvent).where(TakedownEvent.takedown_id.in_(takedown_ids)))
    await session.execute(
        update(Takedown)
        .where(Takedown.reappeared_alert_id.in_(alert_ids))
        .values(reappeared_alert_id=None)
    )
    await session.execute(delete(Takedown).where(Takedown.id.in_(takedown_ids)))
    await session.execute(
        delete(Feedback).where(or_(Feedback.alert_id.in_(alert_ids), Feedback.finding_id.in_(ids)))
    )
    await session.execute(
        update(SuppressionRule)
        .where(SuppressionRule.source_alert_id.in_(alert_ids))
        .values(source_alert_id=None)
    )
    await session.execute(delete(ExposedAccount).where(ExposedAccount.finding_id.in_(ids)))
    await session.execute(delete(Adjudication).where(Adjudication.finding_id.in_(ids)))
    await session.execute(delete(FindingObservation).where(FindingObservation.finding_id.in_(ids)))
    await session.execute(delete(CampaignMember).where(CampaignMember.finding_id.in_(ids)))
    await session.execute(delete(AlertFinding).where(AlertFinding.finding_id.in_(ids)))
    await session.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
    await session.execute(delete(Finding).where(Finding.id.in_(ids)))
    counts.update(alerts=len(alert_ids), evidence=len(evidence), takedowns=len(takedown_ids))
    return PurgeResult(counts, [(str(key), version) for key, version in evidence])


async def apply(session: AsyncSession, cfg: RetentionConfig, *, now: datetime) -> PurgeResult:
    """按配置清理全部数据库类别（原始数据分区由 maintain_partitions 处理）。调用方提交后再删证据文件。"""

    def before(days: int) -> datetime:
        return now - timedelta(days=days)

    counts = {
        "report_contacts": await purge_report_contacts(session, before(cfg.report_contacts_days)),
        "exposed_accounts": await exposure_service.purge(
            session, before(cfg.exposed_accounts_days)
        ),
        "documents": await documents.purge(session, before(cfg.documents_days)),
    }
    found = await purge_findings(
        session, findings_before=before(cfg.findings_days), cases_before=before(cfg.cases_days)
    )
    watch_evidence = (
        await session.execute(
            delete(Evidence)
            .where(
                Evidence.watch_observation_id.is_not(None),
                Evidence.captured_at < before(cfg.findings_days),
            )
            .returning(Evidence.object_key, Evidence.version_id)
        )
    ).all()
    counts.update(found.counts)
    counts["evidence"] += len(watch_evidence)
    alerted = select(AlertFinding.finding_id)
    candidates = await session.execute(
        delete(AccountCandidate)
        .where(
            AccountCandidate.last_seen < before(SOCIAL_CANDIDATE_DAYS),
            or_(
                AccountCandidate.finding_id.is_(None),
                AccountCandidate.finding_id.not_in(alerted),
            ),
        )
        .returning(AccountCandidate.id)
    )
    counts["account_candidates"] = len(candidates.all())
    runs = await session.execute(
        delete(ConnectorRun)
        .where(
            ConnectorRun.started_at < before(cfg.connector_runs_days),
            ConnectorRun.status.not_in(("running", "dispatched")),
        )
        .returning(ConnectorRun.id)
    )
    counts["connector_runs"] = len(runs.all())
    reports = await session.execute(
        delete(Report).where(Report.created_at < before(cfg.reports_days)).returning(Report.id)
    )
    counts["reports"] = len(reports.all())
    objects = [*found.objects, *((str(key), version) for key, version in watch_evidence)]
    # 内容寻址的相同截图可能同时属于告警和监视项，仍有证据引用的版本不能删除。
    if objects:
        kept = set(
            (
                await session.execute(
                    select(Evidence.object_key, Evidence.version_id).where(
                        Evidence.object_key.in_([key for key, _ in objects])
                    )
                )
            ).all()
        )
        objects = [
            (key, version)
            for key, version in objects
            if (key, version) not in kept
            and not any(
                other_key == key and (version is None or other_version is None)
                for other_key, other_version in kept
            )
        ]
    return PurgeResult(counts, list(dict.fromkeys(objects)))


PREVIEW_KEYS = (
    "raw_item_partitions",
    "raw_items_estimate",
    "report_contacts",
    "exposed_accounts",
    "documents",
    "findings",
    "cases",
    "alerts",
    "evidence",
    "takedowns",
    "connector_runs",
    "reports",
)


async def _count(session: AsyncSession, query: Any) -> int:
    return int(await session.scalar(query) or 0)


async def exceeds_batch(session: AsyncSession, cfg: RetentionConfig, *, now: datetime) -> bool:
    """到期的发现是否多于一轮的上限：预览只统计下一轮，之后的清理还会继续删。"""
    candidates = _candidates(
        now - timedelta(days=cfg.findings_days), now - timedelta(days=cfg.cases_days)
    ).limit(policy.current().batches.retention + 1)
    found = await _count(session, select(func.count()).select_from(candidates.subquery()))
    return found > policy.current().batches.retention


async def preview(session: AsyncSession, cfg: RetentionConfig, *, now: datetime) -> dict[str, int]:
    """只读估算下一轮清理量；发现筛选与实际清理共用同一批次上限。"""

    def before(days: int) -> datetime:
        return now - timedelta(days=days)

    await session.execute(text("SET LOCAL statement_timeout = '30s'"))
    partitions = await drop_raw_item_partitions_before(
        await session.connection(), before(cfg.raw_items_days).date(), dry_run=True
    )
    estimate = (
        await _count(
            session,
            text(
                "SELECT coalesce(sum(greatest(reltuples, 0)), 0) "
                "FROM pg_class WHERE relname = ANY(:names)"
            ).bindparams(names=partitions),
        )
        if partitions
        else 0
    )
    ids = await eligible_findings(
        session,
        findings_before=before(cfg.findings_days),
        cases_before=before(cfg.cases_days),
        limit=policy.current().batches.retention,
    )
    links = (
        (
            await session.execute(
                select(AlertFinding.finding_id, AlertFinding.alert_id).where(
                    AlertFinding.finding_id.in_(ids)
                )
            )
        ).all()
        if ids
        else []
    )
    alert_ids = [alert_id for _, alert_id in links]
    cases = len({finding_id for finding_id, _ in links})
    return {
        "raw_item_partitions": len(partitions),
        "raw_items_estimate": estimate,
        "report_contacts": await _count(
            session,
            text(
                "SELECT count(*) FROM finding WHERE match->'context'->>'contact' IS NOT NULL "
                "AND first_seen < :before"
            ).bindparams(before=before(cfg.report_contacts_days)),
        ),
        "exposed_accounts": await _count(
            session,
            select(func.count())
            .select_from(ExposedAccount)
            .where(ExposedAccount.last_seen < before(cfg.exposed_accounts_days)),
        ),
        "documents": await _count(
            session,
            select(func.count())
            .select_from(Document)
            .where(Document.last_seen < before(cfg.documents_days)),
        ),
        "findings": len(ids) - cases,
        "cases": cases,
        "alerts": len(alert_ids),
        "evidence": await _count(
            session,
            select(func.count())
            .select_from(Evidence)
            .where(
                or_(
                    Evidence.finding_id.in_(ids),
                    Evidence.alert_id.in_(alert_ids),
                    and_(
                        Evidence.watch_observation_id.is_not(None),
                        Evidence.captured_at < before(cfg.findings_days),
                    ),
                )
            ),
        ),
        "takedowns": await _count(
            session,
            select(func.count())
            .select_from(Takedown)
            .where(or_(Takedown.finding_id.in_(ids), Takedown.alert_id.in_(alert_ids))),
        )
        if ids
        else 0,
        "connector_runs": await _count(
            session,
            select(func.count())
            .select_from(ConnectorRun)
            .where(
                ConnectorRun.started_at < before(cfg.connector_runs_days),
                ConnectorRun.status.not_in(("running", "dispatched")),
            ),
        ),
        "reports": await _count(
            session,
            select(func.count())
            .select_from(Report)
            .where(Report.created_at < before(cfg.reports_days)),
        ),
    }


async def delete_objects(store: ObjectStore | None, objects: list[tuple[str, str | None]]) -> int:
    """数据库提交后删除证据文件；失败只记日志（文件已无数据库记录引用）。"""
    if not objects:
        return 0
    if store is None:
        log.warning("未配置对象存储：%d 个证据文件无法删除", len(objects))
        return 0
    done = 0
    for key, version in objects:
        try:
            await store.delete(key, version)
            done += 1
        except Exception as e:  # 单个文件失败不影响其余
            log.warning("删除证据文件 %s 失败：%s", key, type(e).__name__)
    return done
