"""受影响账户（设计文档 2.3、2.5）：查询、推给 IT、到期删除。邮箱只经工单通道发给 IT。"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import delete, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.views import load_views
from opti.db.models import Alert, AlertFinding, ExposedAccount, Finding
from opti.tickets.client import PushResult, TicketClient
from opti.tickets.config import TicketsConfig

CATEGORY = "credential_exposure"
ADVICE = "请对以下账户强制修改口令、检查并开启多因素认证、排查近期异常登录，并由 IT 通知员工本人。"


class PushError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


async def counts(session: AsyncSession, finding_id: int) -> tuple[int, int]:
    total = await session.scalar(
        select(func.count())
        .select_from(ExposedAccount)
        .where(ExposedAccount.finding_id == finding_id)
    )
    pending = await session.scalar(
        select(func.count())
        .select_from(ExposedAccount)
        .where(ExposedAccount.finding_id == finding_id, ExposedAccount.pushed_at.is_(None))
    )
    return int(total or 0), int(pending or 0)


async def accounts(session: AsyncSession, finding_id: int) -> list[ExposedAccount]:
    stmt = (
        select(ExposedAccount)
        .where(ExposedAccount.finding_id == finding_id)
        .order_by(ExposedAccount.email)
    )
    return list((await session.scalars(stmt)).all())


async def push(
    session: AsyncSession,
    client: TicketClient,
    alert: Alert,
    finding: Finding,
    *,
    base_url: str,
    now: datetime,
) -> tuple[int, PushResult]:
    """只推送尚未推送的账户；推送失败时不盖章，账户保持待推送，下次重试。"""
    pending = list(
        (
            await session.scalars(
                select(ExposedAccount)
                .where(ExposedAccount.finding_id == finding.id, ExposedAccount.pushed_at.is_(None))
                .order_by(ExposedAccount.email)
                .with_for_update()
            )
        ).all()
    )
    if not pending:
        raise PushError(409, "no accounts are waiting to be pushed")
    views = await load_views(session, [alert.id], base_url)
    if not views:
        raise PushError(404, "alert not found")
    emails = [a.email for a in pending]
    ex = finding.match.get("exposure") or {}
    extra = {
        "exposure": {
            "source": ex.get("source"), "title": ex.get("title"), "domain": ex.get("domain"),
            "breach_date": ex.get("breach_date"), "data_classes": ex.get("data_classes", []),
            "accounts": emails, "advice": ADVICE,
        }
    }  # fmt: skip
    digest = hashlib.sha256("\n".join(emails).encode()).hexdigest()[:12]
    # 已有工单时 Jira / ServiceNow 追加评论，一个告警始终一张单；Webhook 与邮件忽略 existing_ref
    result = await client.push(
        views[0], extra, idempotency_key=f"opti-alert-{alert.id}-accounts-{digest}",
        existing_ref=alert.ticket_ref,
    )  # fmt: skip
    for a in pending:
        a.pushed_at = now
    alert.ticket_pushed_at = alert.ticket_pushed_at or now
    if result.ref and alert.ticket_ref is None:
        alert.ticket_ref = result.ref
    return len(emails), result


async def next_auto_push(
    session: AsyncSession, cfg: TicketsConfig, now: datetime, *, exclude: Sequence[int]
) -> tuple[Alert, Finding] | None:
    if not cfg.auto_push:
        return None
    pending = exists(
        select(ExposedAccount.id).where(
            ExposedAccount.finding_id == Finding.id, ExposedAccount.pushed_at.is_(None)
        )
    )
    stmt = (
        select(Alert, Finding)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .where(
            Alert.status.in_(("open", "acknowledged")),
            Finding.category == CATEGORY,
            Alert.severity.in_([s.value for s in cfg.auto_push]),
            pending,
        )
    )
    if exclude:
        stmt = stmt.where(Alert.id.not_in(list(exclude)))
    row = (
        await session.execute(
            stmt.order_by(Alert.id).limit(1).with_for_update(of=Alert, skip_locked=True)
        )
    ).first()
    return (row[0], row[1]) if row is not None else None


async def purge(session: AsyncSession, before: datetime) -> int:
    """个人信息到期删除（设计文档 2.5）：最后一次出现早于 before 的账户记录。"""
    rows = await session.execute(
        delete(ExposedAccount).where(ExposedAccount.last_seen < before).returning(ExposedAccount.id)
    )
    return len(rows.all())
