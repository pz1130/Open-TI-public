"""可疑域名监视列表（设计文档 10.3）：对尚未上线或已下架的可疑域名定期复查，状态变化时重新评分。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import case, func, null, or_, select, true
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.core.webpages import page_kind
from opti.db import repo
from opti.db.models import DomainObservation, Evidence, Finding, WatchedDomain
from opti.pipeline.enrichment import EnrichmentService

WATCH_ENRICHERS = ("dns", "http_probe", "tls")


class WatchState(StrEnum):
    UNKNOWN = "unknown"
    NO_DNS = "no_dns"
    PARKED = "parked"
    MX_ONLY = "mx_only"
    LIVE = "live"
    PHISHING = "phishing"


HIGH_RISK = frozenset({WatchState.MX_ONLY, WatchState.LIVE, WatchState.PHISHING})
OnChange = Callable[[AsyncSession, WatchedDomain, list[str]], Awaitable[None]]
_DNS_AUTHORITATIVE = frozenset({WatchState.NO_DNS, WatchState.MX_ONLY})


def _section_failed(section: Mapping[str, Any] | None) -> bool:
    """非空 error 才算失败。DNS 成功时 to_dict() 仍带 error=None。"""
    return bool(section and section.get("error"))


def _released(dns: Mapping[str, Any]) -> bool:
    """设计文档 10.3：只有确认名字已不存在才移出。超时、查询错误或仅有 NS 都不算。"""
    if _section_failed(dns):
        return False
    return bool(dns.get("nxdomain")) or dns.get("exists") is False


def classify(dns: Mapping[str, Any], http: Mapping[str, Any] | None) -> WatchState:
    if _section_failed(dns):
        return WatchState.UNKNOWN  # 查询失败不是“域名已不存在”
    if _released(dns):
        return WatchState.NO_DNS
    if not (dns.get("a") or dns.get("aaaa") or dns.get("cname")):
        if dns.get("mx"):
            return WatchState.MX_ONLY
        if dns.get("ns") or dns.get("exists") is True:
            return WatchState.PARKED  # 名字仍在，只是没有地址
        return WatchState.NO_DNS
    kind = page_kind(http or {})
    if kind in {"parking", "non_html", "unavailable"}:
        return WatchState.PARKED
    if kind in {"empty", "challenge"}:
        return WatchState.UNKNOWN
    if kind == "phishing":
        return WatchState.PHISHING
    return WatchState.LIVE


def fingerprint(
    dns: Mapping[str, Any], http: Mapping[str, Any] | None, tls: Mapping[str, Any] | None
) -> dict[str, Any]:
    http = http or {}
    tls = tls or {}
    return {
        "a": sorted(dns.get("a") or []),
        "mx": sorted(dns.get("mx") or []),
        "status": http.get("status"),
        "title": http.get("title"),
        "has_password_field": bool(http.get("has_password_field")),
        "html_sha256": http.get("html_sha256"),
        "tls_sha256": tls.get("sha256"),
        "final_url": http.get("final_url"),
        "page_kind": http.get("page_kind") or page_kind(http) if http else None,
    }


def diff(prev: Mapping[str, Any], cur: Mapping[str, Any]) -> list[str]:
    changes: list[str] = []
    if prev.get("a") != cur.get("a"):
        changes.append("dns_changed")
    if cur.get("mx") and prev.get("mx") != cur.get("mx"):
        changes.append("mx_added")
    if prev.get("status") != cur.get("status"):
        changes.append("http_status_changed")
    if prev.get("title") != cur.get("title"):
        changes.append("title_changed")
    if cur.get("has_password_field") and not prev.get("has_password_field"):
        changes.append("login_form_appeared")
    if prev.get("html_sha256") != cur.get("html_sha256"):
        changes.append("content_changed")
    if prev.get("tls_sha256") != cur.get("tls_sha256"):
        changes.append("certificate_changed")
    if prev.get("final_url") != cur.get("final_url"):
        changes.append("redirect_changed")
    return changes


def _http_kept(prev: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": prev.get("status"),
        "title": prev.get("title"),
        "has_password_field": bool(prev.get("has_password_field")),
        "html_sha256": prev.get("html_sha256"),
        "final_url": prev.get("final_url"),
        "page_kind": prev.get("page_kind"),
    }


def _tls_kept(prev: Mapping[str, Any]) -> dict[str, Any]:
    return {"sha256": prev.get("tls_sha256")}


def _state_if_http_failed(dns: Mapping[str, Any], previous: WatchState) -> WatchState:
    """HTTP 失败不能改判已见过的页面；NXDOMAIN / 仅 MX 仍以 DNS 为准。"""
    indicated = classify(dns, None)
    if indicated in _DNS_AUTHORITATIVE or previous == WatchState.UNKNOWN:
        return indicated
    return previous


def next_interval(state: WatchState, *, created_at: datetime, now: datetime) -> timedelta:
    if state in HIGH_RISK or now - created_at < timedelta(
        days=policy.current().watchlist.young_days
    ):
        return timedelta(hours=policy.current().watchlist.urgent_hours)
    if now - created_at < timedelta(days=policy.current().watchlist.mature_days):
        return timedelta(hours=policy.current().watchlist.normal_hours)
    return timedelta(hours=policy.current().watchlist.dormant_hours)


async def ensure_watched(
    session: AsyncSession, project_id: str, domain: str, *, reason: str, now: datetime
) -> bool:
    insert = pg_insert(WatchedDomain).values(
        project_id=project_id,
        domain=domain,
        reason=reason,
        state=WatchState.UNKNOWN.value,
        created_at=now,
        next_check_at=now,
        last_fingerprint={},
    )
    stmt = insert.on_conflict_do_update(
        constraint="uq_watched_domain_project_id",
        set_={
            "expires_at": None,
            "next_check_at": now,
            "state": WatchState.UNKNOWN.value,
            "last_fingerprint": {},
        },
        where=WatchedDomain.expires_at <= now,
    ).returning(WatchedDomain.id)
    return (await session.execute(stmt)).first() is not None


async def due(
    session: AsyncSession, now: datetime, limit: int = 100, *, project_id: str | None = None
) -> list[WatchedDomain]:
    # 只查候选。调用方须按 Entity -> WatchedDomain 顺序加锁，并复核到期时间。
    # 先锁 WatchedDomain 再由 recheck() 更新 Entity，会与新观测形成反向锁顺序。
    stmt = (
        select(WatchedDomain)
        .where(
            WatchedDomain.next_check_at <= now,
            WatchedDomain.project_id == project_id if project_id is not None else true(),
            or_(WatchedDomain.expires_at.is_(None), WatchedDomain.expires_at > now),
            WatchedDomain.paused_by_suppression.is_(False),
        )
        .order_by(WatchedDomain.next_check_at)
        .limit(limit)
    )
    return list((await session.scalars(stmt)).all())


async def recheck(
    session: AsyncSession,
    wd: WatchedDomain,
    *,
    enrichment: EnrichmentService,
    on_change: OnChange,
    now: datetime,
) -> DomainObservation:
    entity = await repo.upsert_entity(session, "domain", wd.domain, now)
    data: dict[str, Any] = dict(await enrichment.enrich(entity, WATCH_ENRICHERS, force=True))
    dns = data.get("dns") or {}
    http = data.get("http_probe")
    tls = data.get("tls")
    source = "probe"
    if "screenshot" not in enrichment.available:
        screenshot: dict[str, Any] = {"error": "screenshot_disabled"}
    elif not enrichment.visit_allowed("domain", wd.domain):
        screenshot = {"error": "visiting_not_allowed"}
    elif (
        _section_failed(dns)
        or _released(dns)
        or not (dns.get("a") or dns.get("aaaa") or dns.get("cname"))
    ):
        screenshot = {"error": "no_web_address"}
    else:
        screenshot = (await enrichment.enrich(entity, ("screenshot",), force=True)).get(
            "screenshot"
        ) or {"error": "screenshot_unavailable"}
    data["screenshot"] = screenshot
    if not screenshot.get("error") and isinstance(screenshot.get("status"), int):
        http = {
            "url": screenshot.get("url") or (http or {}).get("url"),
            **{
                key: value
                for key, value in screenshot.items()
                if key not in {"artifacts", "method", "captured_at", "blocked"}
                and value is not None
            },
            "reachable": True,
        }
        # 后续重新评分使用浏览器看到的页面，避免仍按 JS 跳转前的空壳页面评分。
        cache = dict(entity.enrichment or {})
        cache["http_probe"] = {"data": http, "fetched_at": now.isoformat()}
        entity.enrichment = cache
        data["http_probe"] = http
        source = "browser"
    data["page"] = {**(http or {}), "verdict": page_kind(http or {}), "source": source}
    previous = WatchState(wd.state)
    prev_fp = dict(wd.last_fingerprint or {})
    if _section_failed(dns):
        # 超时或解析错误：保留上次状态和指纹，不触发重新评分
        state = previous
        fp = prev_fp
    else:
        if _section_failed(http):
            state = _state_if_http_failed(dns, previous)
            http_for_fp: Mapping[str, Any] | None = _http_kept(prev_fp)
        else:
            state = classify(dns, http)
            http_for_fp = http
        tls_for_fp = _tls_kept(prev_fp) if _section_failed(tls) else tls
        fp = fingerprint(dns, http_for_fp, tls_for_fp)

    if previous == WatchState.UNKNOWN:
        # 第一次检查只建立基线；若此时已是高风险状态，也要触发重新评分
        changes = [f"state:unknown->{state.value}"] if state in HIGH_RISK else []
    else:
        changes = diff(prev_fp, fp)
        if previous != state:
            changes.append(f"state:{previous.value}->{state.value}")

    obs = DomainObservation(
        watched_domain_id=wd.id,
        observed_at=now,
        state=state.value,
        fingerprint=fp,
        changes=changes,
        data=data,
    )
    session.add(obs)
    wd.state = state.value
    wd.last_fingerprint = fp
    wd.last_checked_at = now
    wd.next_check_at = now + next_interval(state, created_at=wd.created_at, now=now)
    if (
        _released(dns)
        and now - wd.created_at > timedelta(days=policy.current().watchlist.release_after_days)
        and (wd.expires_at is None or wd.expires_at <= now)
    ):
        wd.expires_at = now  # 确认域名已释放才移出监视
    await session.flush()
    capture_status = await _save_capture(session, obs, screenshot, now)
    obs.data = {**data, "capture_status": capture_status}
    await session.flush()
    finding = await session.scalar(
        select(Finding).where(
            Finding.project_id == wd.project_id,
            Finding.entity_id == entity.id,
        )
    )
    if finding is not None:
        await repo.restore_changed_alerts(session, finding, entity, now)
    if changes:
        await on_change(session, wd, changes)
    return obs


async def _save_capture(
    session: AsyncSession,
    observation: DomainObservation,
    screenshot: Mapping[str, Any],
    now: datetime,
) -> str:
    error = screenshot.get("error")
    if error:
        return (
            str(error)
            if error in {"screenshot_disabled", "visiting_not_allowed", "no_web_address"}
            else "failed"
        )
    try:
        captured = datetime.fromisoformat(str(screenshot["captured_at"]))
        if captured.tzinfo is None:
            captured = captured.replace(tzinfo=UTC)
    except (KeyError, ValueError):
        captured = now
    saved = False
    for ref in screenshot.get("artifacts") or []:
        if not isinstance(ref, dict) or not ref.get("key") or not ref.get("sha256"):
            continue
        name, content_type = ref.get("name"), ref.get("content_type")
        if (name, content_type) not in {("screenshot", "image/png"), ("html", "text/html")}:
            continue
        session.add(
            Evidence(
                finding_id=None,
                watch_observation_id=observation.id,
                kind=str(name),
                object_key=str(ref["key"]),
                sha256=str(ref["sha256"]),
                size=int(ref.get("size") or 0),
                content_type=str(content_type),
                version_id=ref.get("version_id"),
                captured_at=captured,
                node_id=str(ref.get("node_id") or "local"),
                method=str(screenshot.get("method") or "unknown"),
                source_url=screenshot.get("final_url"),
            )
        )
        saved |= name == "screenshot"
    return "done" if saved else "not_saved"


async def watch_until(
    session: AsyncSession,
    project_id: str,
    domain: str,
    *,
    reason: str,
    now: datetime,
    until: datetime,
) -> None:
    """加入或延长监视（下架后监视 90 天，设计文档 12.1）。已过期的重新启用并尽快复查；
    原本无限期监视的（expires_at 为空）保持无限期。"""
    stmt = pg_insert(WatchedDomain).values(
        project_id=project_id,
        domain=domain,
        reason=reason,
        state=WatchState.UNKNOWN.value,
        created_at=now,
        next_check_at=now,
        last_fingerprint={},
        expires_at=until,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_watched_domain_project_id",
        set_={
            "expires_at": case(
                (WatchedDomain.expires_at.is_(None), null()),
                else_=func.greatest(WatchedDomain.expires_at, stmt.excluded.expires_at),
            ),
            "next_check_at": func.least(WatchedDomain.next_check_at, stmt.excluded.next_check_at),
        },
    )
    await session.execute(stmt)
