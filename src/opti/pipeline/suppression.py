"""误报抑制规则（设计文档 6.2、9.3、10.3）：分析员确认的误报或合法第三方，不再生成 Finding 与告警。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import ColumnElement, and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import QueryableAttribute

from opti.core.domains import parse_domain
from opti.db.models import Alert, SuppressionRule, WatchedDomain

KINDS = ("domain", "registered_domain")
SUPPRESSED_VERDICT = "suppressed"  # 由抑制规则自动关闭的告警的研判结论


class SuppressionError(ValueError):
    pass


def normalize_value(kind: str, raw: str) -> str:
    if kind not in KINDS:
        raise SuppressionError(f"未知规则种类：{kind}")
    parts = parse_domain(raw)
    if parts is None:
        raise SuppressionError(f"不是合法域名：{raw}")
    return parts.fqdn if kind == "domain" else parts.registered


async def find_active(
    session: AsyncSession, project_id: str, *, domain: str, registered: str, now: datetime
) -> SuppressionRule | None:
    stmt = (
        select(SuppressionRule)
        .where(
            SuppressionRule.project_id == project_id,
            SuppressionRule.revoked_at.is_(None),
            or_(SuppressionRule.expires_at.is_(None), SuppressionRule.expires_at > now),
            or_(
                and_(SuppressionRule.kind == "domain", SuppressionRule.value == domain),
                and_(
                    SuppressionRule.kind == "registered_domain", SuppressionRule.value == registered
                ),
            ),
        )
        .order_by(SuppressionRule.id)
        .limit(1)
    )
    return (await session.scalars(stmt)).first()


async def create_rule(
    session: AsyncSession,
    *,
    project_id: str,
    kind: str,
    value: str,
    reason: str,
    now: datetime,
    created_by: int | None = None,
    source_alert_id: int | None = None,
    expires_at: datetime | None = None,
) -> SuppressionRule:
    normalized = normalize_value(kind, value)
    rule = SuppressionRule(
        project_id=project_id,
        kind=kind,
        value=normalized,
        reason=reason,
        created_by=created_by,
        source_alert_id=source_alert_id,
        created_at=now,
        expires_at=expires_at,
    )
    session.add(rule)
    await session.flush()
    # 规则有效期间暂停复查；不覆盖下架监视等原有到期时间。
    await session.execute(
        update(WatchedDomain)
        .where(
            WatchedDomain.project_id == project_id,
            or_(WatchedDomain.expires_at.is_(None), WatchedDomain.expires_at > now),
            _covers(kind, normalized, WatchedDomain.domain),
        )
        .values(paused_by_suppression=True)
    )
    return rule


def _covers(
    kind: str, value: str, column: ColumnElement[str] | QueryableAttribute[str]
) -> ColumnElement[bool]:
    if kind == "domain":
        return column == value
    return or_(column == value, column.endswith(f".{value}", autoescape=True))


async def close_covered_alerts(
    session: AsyncSession,
    rule: SuppressionRule,
    *,
    now: datetime,
    exclude_alert_id: int | None = None,
) -> list[int]:
    """规则覆盖的其他未结告警一并关闭：否则它们仍会推送到 Teams，仍会触发对可疑站点的截图。"""
    stmt = (
        select(Alert)
        .where(
            Alert.project_id == rule.project_id,
            Alert.status.in_(("open", "acknowledged")),
            _covers(rule.kind, rule.value, Alert.routing["domain"].astext),
        )
        .order_by(Alert.id)
        .with_for_update()
    )
    if exclude_alert_id is not None:
        stmt = stmt.where(Alert.id != exclude_alert_id)
    closed: list[int] = []
    for alert in (await session.scalars(stmt)).all():
        alert.status, alert.closed_at, alert.updated_at = "closed", now, now
        alert.triage_verdict = SUPPRESSED_VERDICT
        if alert.evidence_status == "pending":
            alert.evidence_status = "none"
        closed.append(alert.id)
    await session.flush()
    return closed


async def revoke(
    session: AsyncSession, rule_id: int, *, user_id: int | None, now: datetime
) -> SuppressionRule | None:
    rule = await session.get(SuppressionRule, rule_id, with_for_update=True)
    if rule is None or rule.revoked_at is not None:
        return None
    rule.revoked_at, rule.revoked_by = now, user_id
    await session.flush()
    await restore_paused(session, now=now, project_id=rule.project_id)
    return rule


async def restore_paused(
    session: AsyncSession, *, now: datetime, project_id: str | None = None
) -> int:
    """恢复不再受有效规则覆盖的监视项；下次复查重新建立基线。"""
    active = (
        select(SuppressionRule.id)
        .where(
            SuppressionRule.project_id == WatchedDomain.project_id,
            SuppressionRule.revoked_at.is_(None),
            or_(SuppressionRule.expires_at.is_(None), SuppressionRule.expires_at > now),
            or_(
                and_(
                    SuppressionRule.kind == "domain",
                    SuppressionRule.value == WatchedDomain.domain,
                ),
                and_(
                    SuppressionRule.kind == "registered_domain",
                    or_(
                        SuppressionRule.value == WatchedDomain.domain,
                        func.right(WatchedDomain.domain, func.length(SuppressionRule.value) + 1)
                        == func.concat(".", SuppressionRule.value),
                    ),
                ),
            ),
        )
        .correlate(WatchedDomain)
        .exists()
    )
    stmt = update(WatchedDomain).where(WatchedDomain.paused_by_suppression.is_(True), ~active)
    if project_id is not None:
        stmt = stmt.where(WatchedDomain.project_id == project_id)
    rows = await session.scalars(
        stmt.values(
            paused_by_suppression=False,
            next_check_at=now,
            state="unknown",
            last_fingerprint={},
        ).returning(WatchedDomain.id)
    )
    return len(rows.all())
