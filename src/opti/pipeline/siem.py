"""SIEM 推送（设计文档 12）：达到级别的新告警推给全部已启用的渠道；逐个渠道记录送达，失败只重发给失败的渠道。"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.core.scoring import Severity, severity_rank
from opti.core.siem import SiemEvent
from opti.db.models import Alert, AlertFinding, Entity, Finding
from opti.pipeline.reports import subject_of
from opti.sharing import SiemSettings
from opti.siem import Sender

WINDOW = timedelta(days=7)  # 超过 7 天仍未送达的告警不再推送（启用 SIEM 时也只补发近 7 天）
BATCH = 500
log = logging.getLogger("opti.siem")


def event_for(alert: Alert, finding: Finding, entity: Entity, base_url: str) -> SiemEvent:
    snap = alert.routing if isinstance(alert.routing, dict) else {}
    score, reasons = snap.get("score"), snap.get("reasons")
    return SiemEvent(
        alert_id=alert.id, project_id=alert.project_id, severity=alert.severity,
        category=str(snap.get("category") or finding.category),
        score=score if isinstance(score, int) else finding.score,
        reasons=tuple(str(r) for r in reasons) if isinstance(reasons, list) else (),
        entity_type=entity.type, entity_value=entity.value, title=subject_of(finding, entity.value),
        created_at=alert.created_at, link=f"{base_url.rstrip('/')}/alerts/{alert.id}",
    )  # fmt: skip


async def push_pending(
    session: AsyncSession,
    senders: Sequence[Sender],
    *,
    cfg: SiemSettings,
    base_url: str,
    now: datetime,
) -> int:
    """返回本次完成全部渠道送达的告警数。"""
    if not senders:
        return 0
    allowed = [s.value for s in Severity if severity_rank(s) >= severity_rank(cfg.min_severity)]
    q = (
        select(Alert, Finding, Entity)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .join(Entity, Entity.id == Finding.entity_id)
        .where(
            Alert.siem_sent_at.is_(None),
            Alert.ignored_at.is_(None),
            or_(
                Finding.category != "certificate_expiry", Alert.status.in_(("open", "acknowledged"))
            ),
            Alert.created_at >= now - timedelta(days=policy.current().delivery.siem_window_days),
            Alert.severity.in_(allowed),
        )
        .order_by(Alert.id)
        .limit(policy.current().batches.siem)
        .with_for_update(of=Alert, skip_locked=True)
    )
    if cfg.categories:
        q = q.where(Finding.category.in_(cfg.categories))
    rows = (await session.execute(q)).all()
    alerts = {a.id: a for a, _, _ in rows}
    events = {a.id: event_for(a, f, e, base_url) for a, f, e in rows}
    for sender in senders:
        pending = [ev for aid, ev in events.items() if sender.name not in alerts[aid].siem_sinks]
        if not pending:
            continue
        try:
            delivered = await sender.send(pending)
        except Exception as e:  # 渠道故障只影响这一轮；不记录异常文本（可能含地址或令牌）
            log.warning("SIEM 渠道 %s 推送失败：%s", sender.name, type(e).__name__)
            delivered = []
        for aid in delivered:
            alerts[aid].siem_sinks = [*alerts[aid].siem_sinks, sender.name]
    names = {s.name for s in senders}
    done = 0
    for alert in alerts.values():
        if names <= set(alert.siem_sinks):
            alert.siem_sent_at = now
            done += 1
    await session.flush()
    return done
