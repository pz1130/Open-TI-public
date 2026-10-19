"""冒充社交账号检查：领取短租约，平台请求在事务外执行，再原子保存候选、发现与告警。

只有名称相似的账号才下载头像；得分不足 20 的不保存。告警不由沙箱取证，证据靠分析员上传截图。
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.scoring import (
    ALERT_FROM,
    AccountFacts,
    Score,
    Severity,
    score_account,
    severity_for,
    severity_rank,
)
from opti.core.social import (
    Avatar,
    Profile,
    Protected,
    compare,
    excluded,
    name_facts,
    search_queries,
)
from opti.core.urls import normalize_url
from opti.db import repo
from opti.db.models import AccountCandidate, Alert, AlertFinding, Finding, ProtectedAccount
from opti.sdk.base import Enricher

if TYPE_CHECKING:
    from opti.pipeline.app import App

LEASE = timedelta(minutes=15)
CHECK_TIMEOUT = 300.0
MAX_CANDIDATES = 200
MAX_AVATARS = 50  # 每轮最多下载的候选头像：受连接器限速约束，整轮须在超时内完成
RECHECK_LIMIT = 50
KEEP_FROM = 20  # 低于低危的候选不保存
NEXT_CHECK = timedelta(hours=24)
RETRY = timedelta(hours=1)
SOURCE = "social_accounts"
ADAPTERS = {"bluesky": "social_bluesky", "mastodon": "social_mastodon"}
ACTIVE = ("open", "acknowledged")
FATAL = frozenset({"adapter_disabled", "search_failed", "scan_timeout"})  # 1 小时后重试


@dataclass(frozen=True)
class Scan:
    id: int
    project_id: str
    protected: Protected
    extra_queries: tuple[str, ...]
    allowed: tuple[str, ...]
    recheck: tuple[tuple[int, str], ...]  # （候选 id，查资料用的标识）
    started: datetime
    known: Mapping[str, tuple[int, Avatar | None]] = field(default_factory=dict)  # 已有候选


@dataclass(frozen=True)
class Hit:
    profile: Profile
    facts: AccountFacts
    score: Score
    avatar: Avatar | None


@dataclass
class Collected:
    protected: Protected
    refreshed: bool = False
    hits: list[Hit] = field(default_factory=list)
    gone: set[int] = field(default_factory=set)
    error: str | None = None
    problems: list[str] = field(default_factory=list)

    def summary(self) -> str | None:
        return self.error or ("; ".join(self.problems) or None)


async def _call(adapter: Enricher, entity_type: str, value: str) -> dict[str, Any]:
    try:
        return await adapter.enrich(entity_type, value)
    except Exception as exc:  # 适配器约定返回 error 字段；远程或意外异常同样按失败处理
        return {"error": type(exc).__name__}


async def _avatar(adapter: Enricher, url: str | None) -> Avatar | None:
    if not url:
        return None
    return Avatar.from_json(await _call(adapter, "social_avatar", url))


async def _refresh(scan: Scan, adapter: Enricher, out: Collected) -> bool:
    """刷新受保护账号自身资料；返回 False 表示账号不存在，本轮不搜索。"""
    stored = scan.protected
    # Bluesky 账号改 handle 后旧 handle 查不到：已知 DID 时按 DID 查
    key = stored.platform_id if stored.platform == "bluesky" and stored.platform_id else None
    result = await _call(adapter, "social_profile", key or stored.handle)
    if result.get("not_found"):
        out.error = "protected_not_found"
        return False
    own = Profile.from_json(result.get("profile"))
    if own is None:
        out.problems.append("profile_failed")
        if stored.avatar is None:
            out.problems.append("official_avatar_missing")
        return True
    avatar = await _avatar(adapter, own.avatar_url) if own.avatar_url else None
    if own.avatar_url and avatar is None:
        avatar = stored.avatar  # 头像下载失败时沿用上次的官方头像
        if avatar is None:
            out.problems.append("official_avatar_missing")
    # Bluesky 改名后以平台返回的 handle 为准（搜索词与页面显示随之更新）
    handle = own.handle if stored.platform == "bluesky" else stored.handle
    out.protected = Protected(
        stored.platform, handle, own.platform_id, own.display_name or None, avatar
    )
    out.refreshed = True
    return True


async def _search(scan: Scan, adapter: Enricher, out: Collected) -> dict[str, Profile]:
    found: dict[str, Profile] = {}
    queries = search_queries(out.protected, scan.extra_queries)
    failed = instances = 0
    for query in queries:
        result = await _call(adapter, "social_search", query)
        instances += int(result.get("failed_instances") or 0)
        if "profiles" not in result:
            failed += 1
            continue
        for raw in result["profiles"]:
            profile = Profile.from_json(raw)
            if profile is not None and len(found) < MAX_CANDIDATES:
                found.setdefault(profile.platform_id, profile)
    if queries and failed == len(queries):
        out.error = "search_failed"
    elif failed:
        out.problems.append(f"search_failed:{failed}")
    if instances and out.error is None:
        out.problems.append(f"instance_failed:{instances}")
    return found


async def _collect(
    scan: Scan, adapter: Enricher, official: tuple[str, ...], now: datetime, out: Collected
) -> None:
    if not await _refresh(scan, adapter, out):
        return
    protected = out.protected
    downloads = 0
    for profile in (await _search(scan, adapter, out)).values():
        if excluded(protected, profile, scan.allowed, official):
            continue
        known_id, stored = scan.known.get(profile.platform_id, (None, None))
        if profile.suspended:
            if known_id is not None:
                out.gone.add(known_id)  # 搜索结果已标为下架：记已消失，不再打分
            continue
        if not name_facts(protected, profile, now).named:
            continue  # 没有名称信号：不保存，也不下载头像
        avatar = None
        if protected.avatar and profile.avatar_url:
            if downloads < MAX_AVATARS:
                downloads += 1
                avatar = await _avatar(adapter, profile.avatar_url)
            avatar = avatar or stored  # 下载失败或超出上限时沿用上次的哈希，避免分数忽高忽低
        facts = compare(protected, profile, avatar, now)
        score = score_account(facts)
        if score.value >= KEEP_FROM:
            out.hits.append(Hit(profile, facts, score, avatar))
    for candidate_id, key in scan.recheck:
        result = await _call(adapter, "social_profile", key)
        current = Profile.from_json(result.get("profile"))
        if result.get("not_found") or (current is not None and current.suspended):
            out.gone.add(candidate_id)


async def collect(
    scan: Scan, adapter: Enricher | None, official: tuple[str, ...], now: datetime
) -> Collected:
    out = Collected(scan.protected)
    if adapter is None:
        out.error = "adapter_disabled"
        return out
    try:
        await asyncio.wait_for(_collect(scan, adapter, official, now, out), CHECK_TIMEOUT)
    except TimeoutError:
        out.error = "scan_timeout"  # 保存超时前已打分的结果，下一轮（约一小时后）继续
    return out


def _lookup_key(platform: str, row: AccountCandidate) -> str:
    # Bluesky 用 DID 查资料（改名不影响）；Mastodon 只能按 user@instance 查
    return row.platform_account_id if platform == "bluesky" else row.handle


async def _finding(
    session: AsyncSession, app: App, scan: Scan, hit: Hit, row: AccountCandidate, now: datetime
) -> Finding:
    url = normalize_url(hit.profile.profile_url) or hit.profile.profile_url
    entity = await repo.upsert_entity(session, "url", url, now)
    previous = await session.scalar(
        select(Finding)
        .where(Finding.project_id == scan.project_id, Finding.entity_id == entity.id)
        .with_for_update()
    )
    # 不带 manual：由 upsert_finding 恢复分析员的说明、类别与级别下限。
    match = {k: v for k, v in (previous.match if previous else {}).items() if k != "manual"}
    # 保留人工提交等其他来源的原因，本来源的原因按本轮信号重写
    kept = [
        r for r in match.get("reasons", []) if isinstance(r, dict) and r.get("source") != SOURCE
    ]
    platform = app.takedown.platform_for(urlsplit(url).hostname)
    match.update(
        {
            "url": url,
            "platform": platform.id if platform else None,
            "social": {
                "platform": scan.protected.platform,
                "protected_id": scan.id,
                "protected_handle": scan.protected.handle,
                "handle": hit.profile.handle,
                "display_name": hit.profile.display_name,
                "registered_at": row.registered_at.isoformat() if row.registered_at else None,
                "bio": hit.profile.bio,
                "avatar_sha256": hit.avatar.sha256 if hit.avatar else None,
                "facts": asdict(hit.facts),
                "gone_at": None,
            },
        }
    )
    score = hit.score
    if previous is not None:
        # 同一冒充号可能被多个受保护账号搜到：发现取各候选中的最高分，避免级别来回跳
        best = await session.scalar(
            select(AccountCandidate)
            .where(AccountCandidate.finding_id == previous.id, AccountCandidate.id != row.id)
            .order_by(AccountCandidate.score.desc())
            .limit(1)
        )
        if best is not None and best.score > score.value:
            breakdown = best.signals.get("breakdown") or {}
            score = Score(best.score, severity_for(best.score), score.category, breakdown)
    match["reasons"] = [*kept, *({"reason": k, "source": SOURCE} for k in score.breakdown)]
    up = await repo.upsert_finding(
        session,
        project_id=scan.project_id,
        entity=entity,
        score=score,
        match=match,
        source=SOURCE,
        now=now,
    )
    # 首次达到中危或级别升高才开新告警（旧告警被取代），且须高于仍未结的告警；
    # 人工定过的更高级别由 upsert 保留
    severity = Severity(up.finding.severity)
    active = (
        await session.scalars(
            select(Alert.severity)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .where(AlertFinding.finding_id == up.finding.id, Alert.status.in_(ACTIVE))
        )
    ).all()
    ceiling = max((severity_rank(s) for s in active), default=-1)
    rank = severity_rank(severity)
    if up.escalated and rank >= severity_rank(ALERT_FROM) and rank > ceiling:
        alert = await repo.open_alert(session, up.finding, severity, now)
        alert.evidence_status = "none"  # 平台主页不由沙箱访问，证据靠分析员上传
    return up.finding


async def _save(app: App, scan: Scan, got: Collected, now: datetime) -> bool:
    async with app.sessions.begin() as session:
        account = await session.get(ProtectedAccount, scan.id, with_for_update=True)
        # 停用、修改或删除期间不落旧结果；崩溃的检查租约最多 15 分钟后可重领。
        if account is None or not account.enabled or account.scan_started_at != scan.started:
            return False
        if got.refreshed:
            handle = got.protected.handle
            if handle != account.handle and not await session.scalar(
                select(ProtectedAccount.id).where(
                    ProtectedAccount.project_id == account.project_id,
                    ProtectedAccount.platform == account.platform,
                    ProtectedAccount.handle == handle,
                )
            ):
                account.handle = handle  # 已有同名登记时保留旧名，避免违反唯一约束
            account.platform_id = got.protected.platform_id
            account.display_name = got.protected.display_name
            avatar = got.protected.avatar
            account.avatar_dhash = avatar.dhash if avatar else None
            account.avatar_sha256 = avatar.sha256 if avatar else None
            account.profile_checked_at = now
        account.error = got.summary()
        account.last_checked_at = now
        account.scan_started_at = None
        account.next_check_at = now + (RETRY if got.error in FATAL else NEXT_CHECK)
        existing = {
            row.platform_account_id: row
            for row in (
                await session.scalars(
                    select(AccountCandidate).where(AccountCandidate.protected_id == scan.id)
                )
            ).all()
        }
        # 固定顺序加锁：并发检查遇到相同冒充号时不互相死锁
        for hit in sorted(got.hits, key=lambda h: h.profile.platform_id):
            p = hit.profile
            row = existing.get(p.platform_id)
            if row is None:
                row = AccountCandidate(
                    protected_id=scan.id,
                    platform_account_id=p.platform_id,
                    first_seen=now,
                    handle=p.handle,
                    profile_url=p.profile_url,
                    score=hit.score.value,
                )
                session.add(row)
                existing[p.platform_id] = row
            row.handle, row.display_name, row.profile_url = p.handle, p.display_name, p.profile_url
            row.registered_at, row.bio = p.registered_at, p.bio
            row.avatar_dhash = hit.avatar.dhash if hit.avatar else None
            row.avatar_sha256 = hit.avatar.sha256 if hit.avatar else None
            row.score = hit.score.value
            row.signals = {"breakdown": dict(hit.score.breakdown), "facts": asdict(hit.facts)}
            row.last_seen = now
            if row.id not in got.gone and not p.suspended:
                row.gone_at = None
            await session.flush()
            row.finding_id = (await _finding(session, app, scan, hit, row, now)).id
        for row in existing.values():
            if row.id in got.gone and row.gone_at is None:
                row.gone_at = now
                if row.finding_id is not None:
                    finding = await session.get(Finding, row.finding_id, with_for_update=True)
                    if finding is not None and isinstance(finding.match.get("social"), dict):
                        social = {**finding.match["social"], "gone_at": now.isoformat()}
                        finding.match = {**finding.match, "social": social}
    return True


async def check_account(app: App, account_id: int, *, force: bool = False) -> bool:
    started = datetime.now(UTC)
    async with app.sessions.begin() as session:
        account = await session.scalar(
            select(ProtectedAccount)
            .where(
                ProtectedAccount.id == account_id,
                ProtectedAccount.project_id == app.rules.project,
            )
            .with_for_update(skip_locked=True)
        )
        if (
            account is None
            or not account.enabled
            or (account.scan_started_at and account.scan_started_at > started - LEASE)
            or (not force and account.next_check_at > started)
        ):
            return False
        flagged = select(AlertFinding.finding_id).join(Alert).where(Alert.status.in_(ACTIVE))
        recheck = (
            await session.scalars(
                select(AccountCandidate)
                .where(
                    AccountCandidate.protected_id == account.id,
                    AccountCandidate.gone_at.is_(None),
                    AccountCandidate.finding_id.in_(flagged),
                )
                .order_by(AccountCandidate.id)
                .limit(RECHECK_LIMIT)
            )
        ).all()
        known = {
            row.platform_account_id: (
                row.id,
                Avatar(row.avatar_dhash, row.avatar_sha256)
                if row.avatar_dhash and row.avatar_sha256
                else None,
            )
            for row in (
                await session.scalars(
                    select(AccountCandidate).where(AccountCandidate.protected_id == account.id)
                )
            ).all()
        }
        stored = (
            Avatar(account.avatar_dhash, account.avatar_sha256)
            if account.avatar_dhash and account.avatar_sha256
            else None
        )
        scan = Scan(
            account.id,
            account.project_id,
            Protected(
                account.platform,
                account.handle,
                account.platform_id,
                account.display_name,
                stored,
            ),
            tuple(account.extra_queries),
            tuple(account.allowed_accounts),
            tuple((row.id, _lookup_key(account.platform, row)) for row in recheck),
            started,
            known,
        )
        account.scan_started_at = started
    adapter = app.enrichment.get(ADAPTERS[scan.protected.platform])
    got = await collect(scan, adapter, tuple(app.rules.domains.official), started)
    return await _save(app, scan, got, datetime.now(UTC))
