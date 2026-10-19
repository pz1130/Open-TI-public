from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.alert_fingerprint import fingerprint as alert_fingerprint
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import WatchedDomain
from opti.pipeline import watchlist as wl
from opti.pipeline.enrichment import EnrichmentService
from opti.sdk.testing import make_context, static_enricher

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
PROJECT = "sample-brand-protection"
DNS = {"exists": True, "a": ["203.0.113.5"], "mx": [], "ns": ["ns1.p.example"]}
PARKED = {"reachable": True, "status": 200, "title": "sbr-loans.com is for sale",
          "has_password_field": False, "brand_terms": [], "html_sha256": "aa"}  # fmt: skip
PHISH = {"reachable": True, "status": 200, "title": "Sample Brand Login",
         "has_password_field": True, "brand_terms": ["Sample Brand"], "html_sha256": "bb"}  # fmt: skip


@pytest.mark.parametrize(
    ("dns", "http", "state"),
    [
        ({"nxdomain": True}, None, wl.WatchState.NO_DNS),
        ({"nxdomain": True, "exists": False, "error": None}, None, wl.WatchState.NO_DNS),
        ({"exists": False, "error": None}, None, wl.WatchState.NO_DNS),
        ({"a": [], "mx": []}, None, wl.WatchState.NO_DNS),
        ({"a": [], "mx": ["10 mx.x"]}, None, wl.WatchState.MX_ONLY),
        # 成功的 DnsRecords.to_dict() 带 error=None；仅有 NS 说明名字还在
        (
            {"exists": True, "error": None, "a": [], "mx": [], "ns": ["ns1.example"]},
            None,
            wl.WatchState.PARKED,
        ),
        ({"error": "TimeoutError", "exists": None, "a": [], "mx": []}, None, wl.WatchState.UNKNOWN),
        ({"nxdomain": True, "error": "TimeoutError"}, None, wl.WatchState.UNKNOWN),
        (DNS, None, wl.WatchState.PARKED),
        (DNS, {"reachable": False}, wl.WatchState.PARKED),
        (DNS, PARKED, wl.WatchState.PARKED),
        (DNS, PHISH, wl.WatchState.PHISHING),
        (DNS, {**PARKED, "title": "Welcome"}, wl.WatchState.LIVE),
        (DNS, {**PHISH, "brand_terms": []}, wl.WatchState.LIVE),
    ],
)
def test_classify(dns: dict[str, Any], http: dict[str, Any] | None, state: wl.WatchState) -> None:
    assert wl.classify(dns, http) == state


def test_diff_reports_meaningful_changes() -> None:
    before = wl.fingerprint(DNS, PARKED, {"present": True, "sha256": "c1"})
    after = wl.fingerprint({**DNS, "mx": ["10 mx.evil"]}, PHISH, {"present": True, "sha256": "c2"})
    assert set(wl.diff(before, after)) == {
        "mx_added", "title_changed", "login_form_appeared", "content_changed", "certificate_changed",
    }  # fmt: skip
    assert wl.diff(before, before) == []


@pytest.mark.parametrize(
    ("state", "age_days", "hours"),
    [(wl.WatchState.PARKED, 1, 4), (wl.WatchState.PARKED, 10, 24), (wl.WatchState.PARKED, 40, 168),
     (wl.WatchState.LIVE, 40, 4), (wl.WatchState.MX_ONLY, 40, 4)],
)  # fmt: skip
def test_next_interval(state: wl.WatchState, age_days: int, hours: int) -> None:
    created = NOW - timedelta(days=age_days)
    assert wl.next_interval(state, created_at=created, now=NOW) == timedelta(hours=hours)


@pytest.mark.db
async def test_ensure_watched_and_due(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await repo.upsert_project(session, sbr_rules)
    assert await wl.ensure_watched(session, PROJECT, "sbr-loans.com", reason="t", now=NOW)
    assert not await wl.ensure_watched(session, PROJECT, "sbr-loans.com", reason="t", now=NOW)
    assert await wl.ensure_watched(
        session, PROJECT, "later.example", reason="t", now=NOW + timedelta(days=1)
    )
    due = await wl.due(session, NOW, limit=10)
    assert [w.domain for w in due] == ["sbr-loans.com"]


def _service(sbr_rules: ProjectRules, http_state: dict[str, Any]) -> EnrichmentService:
    ctx = make_context(sbr_rules)
    return EnrichmentService(
        {
            "dns": static_enricher(ctx, "dns", DNS),
            "http_probe": static_enricher(ctx, "http_probe", lambda _v: dict(http_state)),
            "tls": static_enricher(ctx, "tls", {"present": True, "sha256": "c1"}),
        },
        clock=lambda: NOW,
    )


@pytest.mark.db
async def test_recheck_detects_change(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await repo.upsert_project(session, sbr_rules)
    await wl.ensure_watched(session, PROJECT, "sbr-loans.com", reason="t", now=NOW)
    (wd,) = await wl.due(session, NOW)
    http_state = dict(PARKED)
    svc = _service(sbr_rules, http_state)
    calls: list[list[str]] = []

    async def on_change(_s: AsyncSession, _wd: WatchedDomain, changes: list[str]) -> None:
        calls.append(changes)

    obs = await wl.recheck(session, wd, enrichment=svc, on_change=on_change, now=NOW)
    assert obs.state == "parked" and obs.changes == [] and calls == []
    assert wd.next_check_at == NOW + timedelta(hours=4)

    http_state.update(PHISH)
    later = NOW + timedelta(hours=4)
    obs = await wl.recheck(session, wd, enrichment=svc, on_change=on_change, now=later)
    assert obs.state == "phishing"
    assert "login_form_appeared" in obs.changes and "state:parked->phishing" in obs.changes
    assert calls == [obs.changes]


@pytest.mark.db
async def test_first_check_already_live_triggers_rescore(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    await repo.upsert_project(session, sbr_rules)
    await wl.ensure_watched(session, PROJECT, "sbr-loans.com", reason="t", now=NOW)
    (wd,) = await wl.due(session, NOW)
    calls: list[list[str]] = []

    async def on_change(_s: AsyncSession, _wd: WatchedDomain, changes: list[str]) -> None:
        calls.append(changes)

    await wl.recheck(
        session, wd, enrichment=_service(sbr_rules, dict(PHISH)), on_change=on_change, now=NOW
    )
    assert calls == [["state:unknown->phishing"]]


def _varying_service(
    sbr_rules: ProjectRules,
    dns_state: dict[str, Any],
    http_state: dict[str, Any],
    tls_state: dict[str, Any],
) -> EnrichmentService:
    ctx = make_context(sbr_rules)
    return EnrichmentService(
        {
            "dns": static_enricher(ctx, "dns", lambda _v: dict(dns_state)),
            "http_probe": static_enricher(ctx, "http_probe", lambda _v: dict(http_state)),
            "tls": static_enricher(ctx, "tls", lambda _v: dict(tls_state)),
        },
        clock=lambda: NOW,
    )


@pytest.mark.db
async def test_probe_errors_do_not_expire_or_look_like_changes(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    """查询失败不移出监视；HTTP/TLS 的 error 不当成页面或证书变化。"""
    await repo.upsert_project(session, sbr_rules)
    created = NOW - timedelta(days=91)
    calls: list[list[str]] = []

    async def on_change(_s: AsyncSession, _wd: WatchedDomain, changes: list[str]) -> None:
        calls.append(changes)

    async def take(domain: str) -> WatchedDomain:
        await wl.ensure_watched(session, PROJECT, domain, reason="t", now=created)
        found = [w for w in await wl.due(session, NOW, limit=20) if w.domain == domain]
        assert len(found) == 1
        return found[0]

    gone = {"nxdomain": True, "exists": False, "error": None, "a": [], "mx": [], "ns": []}
    wd = await take("gone-nx.example")
    await wl.recheck(
        session,
        wd,
        enrichment=_varying_service(sbr_rules, gone, dict(PARKED), {"present": False}),
        on_change=on_change,
        now=NOW,
    )
    assert wd.state == "no_dns" and wd.expires_at == NOW
    assert "gone-nx.example" not in [w.domain for w in await wl.due(session, NOW)]

    empty = {"nxdomain": False, "exists": False, "error": None, "a": [], "mx": [], "ns": []}
    wd = await take("gone-empty.example")
    await wl.recheck(
        session,
        wd,
        enrichment=_varying_service(sbr_rules, empty, dict(PARKED), {"present": False}),
        on_change=on_change,
        now=NOW,
    )
    assert wd.state == "no_dns" and wd.expires_at == NOW

    ns_only = {
        "exists": True, "nxdomain": False, "error": None, "a": [], "aaaa": [], "mx": [],
        "ns": ["ns1.example"], "cname": [],
    }  # fmt: skip
    wd = await take("ns-only.example")
    await wl.recheck(
        session,
        wd,
        enrichment=_varying_service(sbr_rules, ns_only, {"reachable": False}, {"present": False}),
        on_change=on_change,
        now=NOW,
    )
    assert wd.expires_at is None and wd.state == "parked"
    assert calls == []

    dns_state = dict(DNS)
    http_state = dict(PARKED)
    tls_state: dict[str, Any] = {"present": True, "sha256": "c1"}
    wd = await take("timeout.example")
    svc = _varying_service(sbr_rules, dns_state, http_state, tls_state)
    obs = await wl.recheck(session, wd, enrichment=svc, on_change=on_change, now=NOW)
    assert obs.state == "parked" and obs.changes == [] and wd.expires_at is None
    baseline = dict(wd.last_fingerprint)

    dns_state.clear()
    dns_state.update({"error": "TimeoutError", "exists": None, "a": [], "mx": []})
    later = NOW + timedelta(days=7)
    obs = await wl.recheck(session, wd, enrichment=svc, on_change=on_change, now=later)
    assert obs.changes == [] and calls == []
    assert wd.state == "parked" and wd.last_fingerprint == baseline and wd.expires_at is None
    assert wd.last_checked_at == later
    assert wd.next_check_at == later + timedelta(days=7)

    http_state.clear()
    http_state.update({"error": "TimeoutError"})
    tls_state.clear()
    tls_state.update({"error": "TimeoutError"})
    dns_state.clear()
    dns_state.update(DNS)
    probed = later + timedelta(days=7)
    obs = await wl.recheck(session, wd, enrichment=svc, on_change=on_change, now=probed)
    assert obs.changes == [] and calls == []
    assert wd.last_fingerprint["status"] == 200
    assert wd.last_fingerprint["title"] == PARKED["title"]
    assert wd.last_fingerprint["html_sha256"] == "aa"
    assert wd.last_fingerprint["tls_sha256"] == "c1"
    assert wd.expires_at is None

    http_state.clear()
    http_state.update(PHISH)
    tls_state.clear()
    tls_state.update({"present": True, "sha256": "c1"})
    caught = probed + timedelta(days=7)
    obs = await wl.recheck(session, wd, enrichment=svc, on_change=on_change, now=caught)
    assert "login_form_appeared" in obs.changes
    assert calls == [obs.changes]


@pytest.mark.db
async def test_watch_until_extends_and_reenables(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    from sqlalchemy import select

    await repo.upsert_project(session, sbr_rules)
    until = NOW + timedelta(days=90)
    await wl.watch_until(session, PROJECT, "a.example", reason="takedown", now=NOW, until=until)
    row = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "a.example"))
    assert row is not None and row.expires_at == until and row.next_check_at == NOW
    # 已过期的重新启用，并尽快复查
    row.expires_at, row.next_check_at = NOW - timedelta(days=1), NOW + timedelta(days=7)
    await session.flush()
    await wl.watch_until(session, PROJECT, "a.example", reason="takedown", now=NOW, until=until)
    await session.refresh(row)
    assert row.expires_at == until and row.next_check_at == NOW
    # 原本无限期监视的保持无限期
    assert await wl.ensure_watched(session, PROJECT, "b.example", reason="typo", now=NOW)
    await wl.watch_until(session, PROJECT, "b.example", reason="takedown", now=NOW, until=until)
    b = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "b.example"))
    assert b is not None
    await session.refresh(b)
    assert b.expires_at is None and b.reason == "typo"


@pytest.mark.db
async def test_important_probe_change_restores_ignored_alert_even_without_rescore(
    session: AsyncSession,
    sbr_rules: ProjectRules,
) -> None:
    await repo.upsert_project(session, sbr_rules)
    await wl.ensure_watched(session, PROJECT, "sbr-loans.com", reason="test", now=NOW)
    (wd,) = await wl.due(session, NOW)
    dns = {**DNS, "aaaa": ["2001:4860:4860::8888"]}
    ctx = make_context(sbr_rules)
    service = EnrichmentService(
        {
            "dns": static_enricher(ctx, "dns", lambda _: dict(dns)),
            "http_probe": static_enricher(ctx, "http_probe", {**PARKED, "title": "Welcome"}),
            "tls": static_enricher(ctx, "tls", {"sha256": "cert"}),
        },
        clock=lambda: NOW,
    )
    calls: list[list[str]] = []

    async def on_change(_s: AsyncSession, _w: WatchedDomain, changes: list[str]) -> None:
        calls.append(changes)

    try:
        await wl.recheck(session, wd, enrichment=service, on_change=on_change, now=NOW)
        entity = await repo.upsert_entity(session, "domain", wd.domain, NOW)
        up = await repo.upsert_finding(
            session,
            project_id=PROJECT,
            entity=entity,
            score=Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {}),
            match={},
            source="test",
            now=NOW,
        )
        alert = await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
        alert.ignored_at = NOW
        alert.ignored_fingerprint = alert_fingerprint(
            up.finding.category, up.finding.severity, up.finding.match, entity.enrichment
        )
        await session.flush()
        calls.clear()
        dns["aaaa"] = ["2606:4700:4700::1111"]
        observation = await wl.recheck(
            session, wd, enrichment=service, on_change=on_change, now=NOW + timedelta(days=1)
        )
        assert observation.changes == [] and calls == []  # 现有 watchlist.diff 不包含 AAAA
        await session.refresh(alert)
        assert alert.ignored_at is None
    finally:
        await ctx.http().aclose()
