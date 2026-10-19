"""仿冒活动（设计文档 8 实体聚类）：配置、定时重算与分析员操作。

重算与所有接口写操作共用同一个事务级咨询锁，保证候选替换与确认、移除不会交错。
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.campaign import (
    GROUP_SIGNALS,
    Confirmed,
    GroupSignal,
    Link,
    Node,
    group,
    group_signals,
    share_counts,
    signature,
)
from opti.db.models import Alert, AlertFinding, Campaign, CampaignMember, Entity, Finding

log = logging.getLogger("opti.campaigns")
CAMPAIGN_LOCK_KEY = 7_041_100_019
ACTIVE_ALERTS = ("open", "acknowledged")
MAX_NODES = 20_000
TRANSITIONS = frozenset(
    {
        ("candidate", "confirmed"),
        ("candidate", "dismissed"),
        ("confirmed", "candidate"),
        ("dismissed", "candidate"),
    }
)
DECISIONS = {
    "accept": ("pending", "member"),
    "reject": ("pending", "excluded"),
    "remove": ("member", "excluded"),
}


class CampaignConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_days: int = Field(default=90, ge=1, le=3650)
    max_share: int = Field(default=10, ge=2, le=1000)
    min_members: int = Field(default=2, ge=2, le=100)
    signals: list[GroupSignal] = Field(default_factory=lambda: list(GROUP_SIGNALS), min_length=1)


def load_campaign_config(path: Path) -> CampaignConfig:
    if not path.exists():
        return CampaignConfig()
    return CampaignConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


class CampaignError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class RecomputeResult:
    candidates: int
    created: int
    removed: int
    pending: int


async def lock(session: AsyncSession) -> None:
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": CAMPAIGN_LOCK_KEY})


def _links(links: tuple[Link, ...]) -> list[dict[str, object]]:
    return [link.as_dict() for link in links]


async def recompute(
    session: AsyncSession, project_id: str, cfg: CampaignConfig, *, now: datetime
) -> RecomputeResult:
    await lock(session)
    rows = (
        await session.execute(
            select(Finding.id, Entity.type, Entity.enrichment)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(Finding.project_id == project_id, Entity.type.in_(("domain", "url")))
        )
    ).all()
    signals = {fid: group_signals(etype, enrichment) for fid, etype, enrichment in rows}
    alert_rows = (
        await session.execute(
            select(
                AlertFinding.finding_id,
                func.max(Alert.created_at),
                func.bool_or(Alert.status.in_(ACTIVE_ALERTS)),
            )
            .join(Alert, Alert.id == AlertFinding.alert_id)
            .where(Alert.project_id == project_id)
            .group_by(AlertFinding.finding_id)
        )
    ).all()
    last_alert = {fid: (created, bool(active)) for fid, created, active in alert_rows}

    confirmed_rows = list(
        (
            await session.scalars(
                select(Campaign)
                .where(Campaign.project_id == project_id, Campaign.state == "confirmed")
                .order_by(Campaign.id)
                .with_for_update()
            )
        ).all()
    )
    members: dict[int, set[int]] = defaultdict(set)
    excluded: dict[int, set[int]] = defaultdict(set)
    if confirmed_rows:
        for cid, fid, state in (
            await session.execute(
                select(
                    CampaignMember.campaign_id, CampaignMember.finding_id, CampaignMember.state
                ).where(CampaignMember.campaign_id.in_([c.id for c in confirmed_rows]))
            )
        ).all():
            (excluded if state == "excluded" else members)[cid].add(fid)
    confirmed = [
        Confirmed(c.id, frozenset(members[c.id]), frozenset(excluded[c.id])) for c in confirmed_rows
    ]
    anchored = {fid for ids in members.values() for fid in ids}
    since = now - timedelta(days=cfg.window_days)
    nodes = [
        Node(fid, sig, last_alert.get(fid, (since, False))[1])
        for fid, sig in signals.items()
        if fid in anchored or (fid in last_alert and last_alert[fid][0] >= since)
    ]
    if len(nodes) > MAX_NODES:
        log.warning("仿冒活动重算：%s 个发现参与归组，超过 %s", len(nodes), MAX_NODES)
    result = group(
        nodes,
        share_counts(signals.values()),
        confirmed,
        max_share=cfg.max_share,
        min_members=cfg.min_members,
        enabled=frozenset(cfg.signals),
    )

    pending = 0
    by_id = {c.id: c for c in confirmed_rows}
    for cid, ext in result.extensions.items():
        campaign = by_id[cid]
        for fid in ext.finding_ids:
            session.add(
                CampaignMember(
                    campaign_id=cid,
                    finding_id=fid,
                    state="pending",
                    signals=_links(ext.links.get(fid, ())),
                    added_at=now,
                )
            )
        ignored = ext.ignored_dicts()
        if ext.finding_ids or campaign.ignored != ignored:
            campaign.updated_at = now
        campaign.ignored = ignored
        pending += len(ext.finding_ids)

    existing = list(
        (
            await session.scalars(
                select(Campaign)
                .where(Campaign.project_id == project_id, Campaign.state == "candidate")
                .with_for_update()
            )
        ).all()
    )
    by_signature = {c.signature: c for c in existing}
    dismissed = set(
        (
            await session.scalars(
                select(Campaign.signature).where(
                    Campaign.project_id == project_id, Campaign.state == "dismissed"
                )
            )
        ).all()
    )
    kept: set[int] = set()
    created = 0
    for grp in result.candidates:
        sig = signature(grp.finding_ids)
        if sig in dismissed:
            continue
        ignored = grp.ignored_dicts()
        found = by_signature.get(sig)
        if found is None:
            found = Campaign(
                project_id=project_id, state="candidate", signature=sig, ignored=ignored,
                created_at=now, updated_at=now,
            )  # fmt: skip
            session.add(found)
            await session.flush()
            for fid in grp.finding_ids:
                session.add(
                    CampaignMember(
                        campaign_id=found.id,
                        finding_id=fid,
                        state="member",
                        signals=_links(grp.links.get(fid, ())),
                        added_at=now,
                    )
                )
            created += 1
        else:
            changed = found.ignored != ignored
            for member in (
                await session.scalars(
                    select(CampaignMember).where(CampaignMember.campaign_id == found.id)
                )
            ).all():
                links = _links(grp.links.get(member.finding_id, ()))
                if member.signals != links:
                    member.signals = links
                    changed = True
            found.ignored = ignored
            if changed:
                found.updated_at = now
        kept.add(found.id)
    stale = [c.id for c in existing if c.id not in kept]
    if stale:
        await session.execute(delete(CampaignMember).where(CampaignMember.campaign_id.in_(stale)))
        await session.execute(delete(Campaign).where(Campaign.id.in_(stale)))
    await session.flush()
    return RecomputeResult(
        candidates=len(kept), created=created, removed=len(stale), pending=pending
    )


async def transition(
    session: AsyncSession, campaign: Campaign, to: str, *, user_id: int, now: datetime
) -> None:
    """调用方须已持有咨询锁并锁定活动行。"""
    if (campaign.state, to) not in TRANSITIONS:
        raise CampaignError(409, f"cannot change campaign from {campaign.state} to {to}")
    if to == "confirmed":
        own = select(CampaignMember.finding_id).where(
            CampaignMember.campaign_id == campaign.id, CampaignMember.state == "member"
        )
        conflict = await session.scalar(
            select(CampaignMember.finding_id)
            .join(Campaign, Campaign.id == CampaignMember.campaign_id)
            .where(
                Campaign.project_id == campaign.project_id,
                Campaign.state == "confirmed",
                Campaign.id != campaign.id,
                CampaignMember.state.in_(("member", "pending")),
                CampaignMember.finding_id.in_(own),
            )
            .limit(1)
        )
        if conflict is not None:
            raise CampaignError(409, "a member already belongs to another confirmed campaign")
        campaign.confirmed_at = now
        campaign.confirmed_by = user_id
    elif to == "candidate":
        await session.execute(
            delete(CampaignMember).where(
                CampaignMember.campaign_id == campaign.id, CampaignMember.state == "excluded"
            )
        )
        await session.execute(
            update(CampaignMember)
            .where(CampaignMember.campaign_id == campaign.id, CampaignMember.state == "pending")
            .values(state="member")
        )
        ids = (
            await session.scalars(
                select(CampaignMember.finding_id).where(CampaignMember.campaign_id == campaign.id)
            )
        ).all()
        campaign.signature = signature(ids)
        campaign.confirmed_at = None
        campaign.confirmed_by = None
    campaign.state = to
    campaign.updated_at = now
    await session.flush()


async def decide(
    session: AsyncSession,
    campaign: Campaign,
    finding_id: int,
    decision: str,
    *,
    user_id: int,
    now: datetime,
) -> None:
    """调用方须已持有咨询锁并锁定活动行。"""
    if campaign.state != "confirmed":
        raise CampaignError(409, "campaign not confirmed")
    if decision not in DECISIONS:
        raise CampaignError(409, f"unknown decision {decision}")
    member = await session.get(
        CampaignMember, (campaign.id, finding_id), with_for_update=True, populate_existing=True
    )
    if member is None:
        raise CampaignError(404, "member not found")
    before, after = DECISIONS[decision]
    if member.state != before:
        raise CampaignError(409, f"member is {member.state}")
    member.state = after
    member.decided_by = user_id
    member.decided_at = now
    campaign.updated_at = now
    await session.flush()
