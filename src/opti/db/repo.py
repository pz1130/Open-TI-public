"""仓储函数：所有写操作都是幂等的（设计文档 3.3、19：至少一次投递 + 幂等处理）。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.alert_fingerprint import changed, fingerprint
from opti.core.attack import candidate_tags
from opti.core.config import ProjectRules
from opti.core.scoring import Score, Severity, severity_for, severity_rank
from opti.db.models import (
    Alert,
    AlertFinding,
    ConnectorRun,
    Entity,
    Finding,
    FindingObservation,
    Project,
    RawItemRow,
)
from opti.pipeline import metrics
from opti.sdk.models import RawItem

# 证据优先（设计文档 3.3）：高危的域名类告警自动截图存证
EVIDENCE_SEVERITIES = frozenset({Severity.HIGH.value, Severity.CRITICAL.value})
EVIDENCE_CATEGORIES = frozenset(
    {"typosquat_domain", "phishing_site", "reported_phishing", "clone_site"}
)


async def upsert_project(session: AsyncSession, rules: ProjectRules) -> None:
    # 热路径上对未变化的 Project 执行 UPDATE 会在整个富化事务内持有行锁，
    # 同项目不同实体因而全局串行，并与监视复查形成反向锁顺序。
    insert = (
        pg_insert(Project)
        .values(id=rules.project, name=rules.project, authorization_ref=rules.authorization_ref)
        .on_conflict_do_nothing(index_elements=[Project.id])
    )
    await session.execute(insert)
    await session.execute(
        update(Project)
        .where(
            Project.id == rules.project,
            Project.authorization_ref.is_distinct_from(rules.authorization_ref),
        )
        .values(authorization_ref=rules.authorization_ref)
    )


async def insert_raw_item(session: AsyncSession, item: RawItem) -> bool:
    stmt = (
        pg_insert(RawItemRow)
        .values(
            item_id=item.item_id,
            fetched_at=item.fetched_at,
            connector_id=item.connector_id,
            source_item_id=item.source_item_id,
            url=item.url,
            payload=item.payload,
            project_ids=list(item.project_ids),
        )
        .on_conflict_do_nothing()
        .returning(RawItemRow.item_id)
    )
    return (await session.execute(stmt)).first() is not None


async def upsert_entity(session: AsyncSession, type_: str, value: str, now: datetime) -> Entity:
    stmt = (
        pg_insert(Entity)
        .values(type=type_, value=value, first_seen=now, last_seen=now, enrichment={})
        .on_conflict_do_update(constraint="uq_entity_type", set_={"last_seen": now})
        .returning(Entity)
    )
    result = await session.scalars(stmt, execution_options={"populate_existing": True})
    return result.one()


@dataclass(frozen=True)
class FindingUpsert:
    finding: Finding
    created: bool
    escalated: bool


async def upsert_finding(
    session: AsyncSession,
    *,
    project_id: str,
    entity: Entity,
    score: Score,
    match: Mapping[str, Any],
    source: str,
    now: datetime,
) -> FindingUpsert:
    values: dict[str, Any] = {
        "category": score.category.value,
        "score": score.value,
        "severity": score.severity.value,
        "score_breakdown": dict(score.breakdown),
        "match": dict(match),
    }
    # 并发安全：先尝试插入，唯一约束冲突时走更新路径
    ins = (
        pg_insert(Finding)
        .values(
            project_id=project_id,
            entity_id=entity.id,
            status="new",
            sources=[source],
            first_seen=now,
            last_seen=now,
            **values,
        )
        .on_conflict_do_nothing(constraint="uq_finding_project_id")
        .returning(Finding.id)
    )
    new_id = (await session.execute(ins)).scalar_one_or_none()
    if new_id is not None:
        created = await session.get(Finding, new_id)
        assert created is not None
        return FindingUpsert(created, created=True, escalated=True)

    finding = (
        await session.scalars(
            select(Finding)
            .where(Finding.project_id == project_id, Finding.entity_id == entity.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).one()
    manual = finding.match.get("manual") if isinstance(finding.match, dict) else None
    if isinstance(manual, dict) and "manual" not in values["match"]:
        # 人工提交的说明、平台标记与分析员选定的类别、级别不能被之后的自动观测覆盖
        values["match"] = {
            **values["match"],
            "manual": manual,
            "platform": finding.match.get("platform"),
        }
        values["category"] = str(manual.get("category") or finding.category)
        floor = manual.get("score")
        if isinstance(floor, int) and score.value < floor:
            values.update(
                score=floor, severity=severity_for(floor).value, score_breakdown={"manual": floor}
            )
    escalated = severity_rank(Severity(values["severity"])) > severity_rank(
        Severity(finding.severity)
    )
    for key, value in values.items():
        setattr(finding, key, value)
    finding.last_seen = now
    if source not in finding.sources:
        finding.sources = [*finding.sources, source]
    await session.flush()
    await restore_changed_alerts(session, finding, entity, now)
    return FindingUpsert(finding, created=False, escalated=escalated)


async def restore_changed_alerts(
    session: AsyncSession,
    finding: Finding,
    entity: Entity,
    now: datetime,
) -> None:
    rows = (
        await session.scalars(
            select(Alert)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .where(
                AlertFinding.finding_id == finding.id,
                Alert.ignored_at.is_not(None),
                Alert.status.in_(("open", "acknowledged")),
            )
            .order_by(Alert.id)
            .with_for_update(of=Alert)
        )
    ).all()
    if not rows:
        return
    current = fingerprint(
        finding.category, finding.severity, finding.match, entity.enrichment or {}
    )
    for alert in rows:
        if changed(alert.ignored_fingerprint, current):
            alert.ignored_at, alert.ignored_fingerprint = None, {}
            alert.updated_at = now
            alert.routing = _alert_snapshot(finding, entity.value)
            alert.severity = finding.severity
    await session.flush()


async def add_observation(
    session: AsyncSession, finding: Finding, item: RawItem, score: int, now: datetime
) -> None:
    await session.execute(
        pg_insert(FindingObservation)
        .values(
            finding_id=finding.id,
            item_id=item.item_id,
            connector_id=item.connector_id,
            observed_at=now,
            score=score,
        )
        .on_conflict_do_nothing()
    )


async def has_project_observation(session: AsyncSession, project_id: str, item_id: str) -> bool:
    """本项目是否已对这条原始数据记过观测。重放按 (project_id, item_id) 判断，不看其他项目。"""
    stmt = (
        select(FindingObservation.id)
        .join(Finding, FindingObservation.finding_id == Finding.id)
        .where(Finding.project_id == project_id, FindingObservation.item_id == item_id)
        .limit(1)
    )
    return (await session.scalar(stmt)) is not None


def _alert_snapshot(finding: Finding, domain: str) -> dict[str, Any]:
    if finding.category == "certificate_expiry":
        domain = str(finding.match.get("domain") or domain)
    raw = finding.match.get("reasons", [])
    reasons = sorted({str(item.get("reason")) for item in raw if isinstance(item, dict)})
    return {
        "score": finding.score,
        "category": finding.category,
        "reasons": reasons,
        "domain": domain,
        "attack_techniques": candidate_tags(finding.category),
        **({"url": finding.match["url"]} if isinstance(finding.match.get("url"), str) else {}),
    }


async def open_alert(
    session: AsyncSession, finding: Finding, severity: Severity, now: datetime
) -> Alert:
    previous = select(AlertFinding.alert_id).where(AlertFinding.finding_id == finding.id)
    active = Alert.status.in_(("open", "acknowledged"))
    # 同一关键事实重复开告警时沿用忽略，防止去重/重建绕过用户的忽略选择。
    prior = await session.scalar(
        select(Alert)
        .where(Alert.id.in_(previous), active)
        .order_by(Alert.id.desc())
        .limit(1)
        .with_for_update()
    )
    assignee_id = await session.scalar(
        select(Alert.assignee_id)
        .where(Alert.id.in_(previous), active, Alert.assignee_id.is_not(None))
        .order_by(Alert.id.desc())
        .limit(1)
    )
    await session.execute(
        update(Alert).where(Alert.id.in_(previous), active).values(status="superseded")
    )
    entity = await session.get(Entity, finding.entity_id)
    inherit_ignore = (
        prior is not None
        and prior.ignored_at is not None
        and not changed(
            prior.ignored_fingerprint,
            fingerprint(
                finding.category,
                severity.value,
                finding.match,
                entity.enrichment if entity is not None else {},
            ),
        )
    )
    # 冻结打开当时的评分、类别、原因和域名。finding 之后会被新观测覆盖，重试不能读新值。
    alert = Alert(
        evidence_status=(
            "pending"
            if severity.value in EVIDENCE_SEVERITIES
            and finding.category in EVIDENCE_CATEGORIES
            and entity is not None
            and entity.type in ("domain", "url")
            else "none"
        ),
        project_id=finding.project_id,
        severity=severity.value,
        status="open",
        created_at=now,
        routing=_alert_snapshot(finding, entity.value if entity is not None else ""),
        assignee_id=assignee_id,
        ignored_at=prior.ignored_at if prior is not None and inherit_ignore else None,
        ignored_fingerprint=prior.ignored_fingerprint
        if prior is not None and inherit_ignore
        else {},
    )
    session.add(alert)
    await session.flush()
    session.add(AlertFinding(alert_id=alert.id, finding_id=finding.id))
    await metrics.record_sample(session, finding, entity, now)
    await session.flush()
    return alert


async def start_run(session: AsyncSession, connector_id: str, now: datetime) -> int:
    run = ConnectorRun(
        connector_id=connector_id, started_at=now, status="running", items=0, errors=0, message=""
    )
    session.add(run)
    await session.flush()
    return run.id


async def finish_run(
    session: AsyncSession,
    run_id: int,
    *,
    status: str,
    items: int,
    errors: int,
    message: str,
    now: datetime,
) -> None:
    await session.execute(
        update(ConnectorRun)
        .where(ConnectorRun.id == run_id)
        .values(status=status, items=items, errors=errors, message=message, ended_at=now)
    )
