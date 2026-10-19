"""单条与批量研判共用的告警状态修改（设计文档 9.3）。审计由调用方记录。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import Alert, Feedback

ACTIVE_STATUSES = ("open", "acknowledged")
CLOSING_VERDICTS = frozenset({"false_positive", "duplicate", "benign_known", "out_of_scope"})
SUPPRESSIBLE_VERDICTS = frozenset({"false_positive", "benign_known"})


def apply_status(alert: Alert, status: str, now: datetime) -> None:
    alert.status = status
    alert.closed_at = now if status == "closed" else None
    alert.updated_at = now


def apply_verdict(
    session: AsyncSession,
    alert: Alert,
    finding_id: int,
    *,
    user_id: int,
    verdict: str,
    reason: str,
    now: datetime,
) -> None:
    session.add(
        Feedback(
            alert_id=alert.id,
            finding_id=finding_id,
            user_id=user_id,
            verdict=verdict,
            reason=reason,
            created_at=now,
        )
    )
    alert.triage_verdict = verdict
    if alert.status != "superseded":
        apply_status(alert, "closed" if verdict in CLOSING_VERDICTS else "acknowledged", now)
    alert.updated_at = now
