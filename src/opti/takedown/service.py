"""下架投诉状态机（设计文档 12.1）：四眼审批、SLA、下架后监视 90 天、复活后重新告警。

平台不自动发送投诉：submitted 由人工在机构邮箱发出后标记。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.views import Notice, defang
from opti.core import policy
from opti.core.scoring import Severity, severity_rank
from opti.db import repo
from opti.db.models import (
    Alert,
    DomainObservation,
    Entity,
    Finding,
    Takedown,
    TakedownEvent,
    WatchedDomain,
)
from opti.pipeline import watchlist
from opti.pipeline.enrichment import EnrichmentService
from opti.takedown.config import TakedownConfig
from opti.takedown.hosting import ip_literal
from opti.takedown.render import SUBJECT_MAX, Material
from opti.takedown.targets import Target, escalations

TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"approved", "cancelled"}),
    "approved": frozenset({"submitted", "draft", "cancelled"}),
    "submitted": frozenset({"acknowledged", "removed", "rejected"}),
    "acknowledged": frozenset({"removed", "rejected"}),
    "removed": frozenset({"reappeared"}),
}
ACTIVE_STATES = ("draft", "approved", "submitted", "acknowledged")
OPEN_STATES = ("submitted", "acknowledged")  # 等对方处理、受 SLA 约束
LIVE_STATES = frozenset({"live", "phishing"})


class TakedownError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Actor:
    user_id: int | None  # None 表示系统
    username: str


SYSTEM = Actor(None, "system")


async def _event(
    session: AsyncSession, td: Takedown, actor: Actor, from_state: str | None, to_state: str,
    now: datetime, note: str = "",
) -> None:  # fmt: skip
    session.add(
        TakedownEvent(
            takedown_id=td.id, ts=now, actor=actor.username, from_state=from_state,
            to_state=to_state, note=note[:2000],
        )
    )  # fmt: skip
    await session.flush()


async def create(
    session: AsyncSession,
    *,
    project_id: str,
    alert_id: int,
    finding_id: int,
    host: str,
    target: Target,
    material: Material,
    language: str,
    actor: Actor,
    now: datetime,
) -> Takedown:
    if actor.user_id is None:
        raise TakedownError(403, "a takedown must be drafted by a user")
    await session.scalar(select(Alert.id).where(Alert.id == alert_id).with_for_update())
    existing = await session.scalar(
        select(Takedown.id).where(
            Takedown.alert_id == alert_id,
            Takedown.target["id"].astext == target.id,
            Takedown.state.in_(ACTIVE_STATES),
        )
    )
    if existing is not None:
        raise TakedownError(409, f"takedown #{existing} for this target is still active")
    td = Takedown(
        project_id=project_id, alert_id=alert_id, finding_id=finding_id, domain=host,
        target=target.to_dict(), language=language, subject=" ".join(material.subject.split())[:SUBJECT_MAX],
        body=material.body, state="draft", created_by=actor.user_id, created_at=now, updated_at=now,
        reminders=0,  # 显式赋值：有服务端默认值的列在 flush 后会过期，异步会话中再访问会触发隐式 IO
    )  # fmt: skip
    session.add(td)
    await session.flush()
    await _event(session, td, actor, None, "draft", now, target.name)
    return td


def _due(cfg: TakedownConfig, td: Takedown, now: datetime) -> datetime | None:
    hours = cfg.sla_hours.get(str(td.target.get("kind")), 0)
    return now + timedelta(hours=hours) if hours > 0 else None


async def _move(
    session: AsyncSession, td: Takedown, to: str, *, actor: Actor, now: datetime,
    cfg: TakedownConfig, note: str = "", external_ref: str | None = None,
) -> None:  # fmt: skip
    prev = td.state
    if to == "approved":
        td.approved_by, td.approved_at = actor.user_id, now
    elif to == "draft":
        td.approved_by, td.approved_at = None, None
    elif to == "submitted":
        td.submitted_at, td.due_at = now, _due(cfg, td, now)
    elif to == "acknowledged":
        td.acknowledged_at, td.due_at = now, _due(cfg, td, now)
    elif to in ("removed", "rejected"):
        td.resolved_at, td.due_at = now, None
    if external_ref and external_ref.strip():
        td.external_ref = external_ref.strip()[:200]
    td.state, td.updated_at = to, now
    await _event(session, td, actor, prev, to, now, note)
    if to == "removed" and td.target.get("kind") != "platform" and ip_literal(td.domain) is None:
        await watchlist.watch_until(
            session, td.project_id, td.domain, reason=f"takedown #{td.id} removed",
            now=now, until=now + timedelta(days=policy.current().watchlist.removed_watch_days),
        )  # fmt: skip


async def transition(
    session: AsyncSession,
    td: Takedown,
    to: str,
    *,
    actor: Actor,
    now: datetime,
    cfg: TakedownConfig,
    note: str = "",
    external_ref: str | None = None,
) -> None:
    if to not in TRANSITIONS.get(td.state, frozenset()):
        raise TakedownError(409, f"cannot move a takedown from {td.state} to {to}")
    if to == "reappeared" and actor.user_id is not None:
        raise TakedownError(403, "only the system marks a takedown as reappeared")
    if to == "approved" and actor.user_id == td.created_by:
        raise TakedownError(403, "four-eyes rule: the drafter cannot approve their own takedown")
    await _move(
        session, td, to, actor=actor, now=now, cfg=cfg, note=note, external_ref=external_ref
    )


async def edit(
    session: AsyncSession, td: Takedown, *, subject: str, body: str, actor: Actor, now: datetime
) -> None:
    """审批后修改内容：回到草稿并清除审批（四眼原则针对的是最终发出的内容）。"""
    if actor.user_id is None:
        raise TakedownError(403, "a user must edit the material")
    if td.state not in ("draft", "approved"):
        raise TakedownError(409, f"cannot edit a {td.state} takedown")
    if td.state == "approved":
        await _move(
            session,
            td,
            "draft",
            actor=actor,
            now=now,
            cfg=TakedownConfig(),
            note="edited after approval",
        )
    td.subject = " ".join(subject.split())[:SUBJECT_MAX]
    td.body = body
    td.created_by = actor.user_id  # 最终材料的起草人；原始创建人保留在事件历史中
    await _event(session, td, actor, td.state, td.state, now, "material edited")
    td.updated_at = now


def came_back(obs: DomainObservation) -> bool:
    """复活：仍是钓鱼页，或从不可访问变为可访问。一直可访问、只是内容变了（如"账户已暂停"页）不算。"""
    # 只看探测结果是否失败；截图等取证状态（如未启用截图）不影响复活判断
    data = obs.data or {}
    if any(
        isinstance(data.get(key), dict) and data[key].get("error")
        for key in watchlist.WATCH_ENRICHERS
    ):
        return False
    if obs.state == "phishing":
        return True
    for change in obs.changes:
        if change.startswith("state:"):
            before, _, after = change.removeprefix("state:").partition("->")
            return before in {"no_dns", "mx_only"} and after in LIVE_STATES
    return False


async def on_recheck(
    session: AsyncSession,
    wd: WatchedDomain,
    obs: DomainObservation,
    *,
    now: datetime,
    enrichment: EnrichmentService | None = None,
) -> list[int]:
    """监视复查后调用：已下架的域名复活时把相关投诉标为复活，并为每个 Finding 开一个新告警（至少 High）。"""
    rows = (
        await session.scalars(
            select(Takedown)
            .where(
                Takedown.project_id == wd.project_id,
                Takedown.domain == wd.domain,
                Takedown.state == "removed",
                Takedown.resolved_at < obs.observed_at,
            )
            .order_by(Takedown.id)
            .with_for_update()
        )
    ).all()
    opened: dict[int, int] = {}
    for td in rows:
        finding = await session.get(Finding, td.finding_id)
        assert finding is not None
        entity = await session.get(Entity, finding.entity_id)
        assert entity is not None
        if td.finding_id not in opened:
            if entity.type == "url":
                if enrichment is None:
                    continue
                previous = (entity.enrichment or {}).get("http_probe", {})
                old = previous.get("data", {})
                data = (await enrichment.enrich(entity, ("http_probe",), force=True)).get(
                    "http_probe", {}
                )
                fresh_live = (
                    data.get("reachable") is True
                    and isinstance(data.get("status"), int)
                    and data["status"] < 400
                )
                phishing = bool(data.get("has_password_field") and data.get("brand_terms"))
                # Shared hosting: only the original URL can establish reappearance.
                was_offline = (
                    old.get("reachable") is False
                    and not old.get("error")
                    and td.resolved_at is not None
                    and previous.get("fetched_at", "") > td.resolved_at.isoformat()
                )
                if data.get("error") or not fresh_live or not (phishing or was_offline):
                    continue
            elif not came_back(obs):
                continue

            finding = await session.get(Finding, td.finding_id)
            assert finding is not None
            severity = Severity(finding.severity)
            if severity_rank(severity) < severity_rank(Severity.HIGH):
                severity = Severity.HIGH
            alert = await repo.open_alert(session, finding, severity, now)
            alert.routing = {**alert.routing, "reappeared_from_takedown": td.id}
            opened[td.finding_id] = alert.id
        td.reappeared_alert_id = opened[td.finding_id]
        await transition(
            session, td, "reappeared", actor=SYSTEM, now=now, cfg=TakedownConfig(),
            note=f"watch state: {obs.state}",
        )  # fmt: skip
    await session.flush()
    return list(opened.values())


async def overdue(session: AsyncSession, now: datetime, *, limit: int) -> list[Takedown]:
    stmt = (
        select(Takedown)
        .where(
            Takedown.state.in_(OPEN_STATES), Takedown.due_at.is_not(None), Takedown.due_at <= now
        )
        .order_by(Takedown.due_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return list((await session.scalars(stmt)).all())


async def mark_reminded(
    session: AsyncSession, td: Takedown, cfg: TakedownConfig, now: datetime
) -> None:
    td.reminders += 1
    hours = cfg.sla_hours.get(str(td.target.get("kind")), 0)
    td.due_at = (
        now + timedelta(hours=hours) if hours > 0 and td.reminders < cfg.max_reminders else None
    )
    await _event(session, td, SYSTEM, td.state, td.state, now, f"SLA reminder {td.reminders}")


def reminder_notice(cfg: TakedownConfig, td: Takedown, base_url: str) -> Notice:
    target = Target.from_dict(td.target)
    upgrade = "；".join(
        f"{t.name} {t.url or t.email or ''}".strip() for t in escalations(cfg, target.kind)
    )
    since = td.acknowledged_at or td.submitted_at
    return Notice(
        title=f"下架投诉 #{td.id} 超过 SLA 未处理",
        facts=(
            ("投诉对象", target.name),
            ("域名", defang(td.domain)),
            ("状态", td.state),
            ("提交或受理时间", since.isoformat() if since else "-"),
            ("已提醒次数", str(td.reminders + 1)),
            ("建议升级", upgrade or "-"),
        ),
        link=f"{base_url.rstrip('/')}/takedowns?id={td.id}",
    )
