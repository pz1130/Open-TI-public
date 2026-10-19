from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from opti.core.config import ProjectRules
from opti.db import repo
from opti.db.models import Alert, CertificateMonitor, Entity, Finding, MonitoredCertificate
from opti.pipeline import certificates
from opti.pipeline.app import App, build_app
from opti.sdk.testing import make_context, static_enricher
from opti.settings import Settings

pytestmark = pytest.mark.db


@pytest.fixture
async def world(
    clean_db: str, sbr_rules: ProjectRules, sbr_rules_path: Path
) -> AsyncIterator[tuple[App, dict[str, Any], int]]:
    now = datetime.now(UTC)
    state: dict[str, Any] = {
        "end": now + timedelta(days=20),
        "sha": "first",
        "failure": False,
        "discovery_failure": False,
    }
    ctx = make_context(sbr_rules)

    def tls(host: str) -> dict[str, Any]:
        if state["failure"]:
            return {"present": False, "error": "TimeoutError"}
        return {
            "present": True,
            "not_after": state["end"].isoformat(),
            "sha256": state["sha"],
            "issuer_o": "Test CA",
        }

    discovery = static_enricher(
        ctx,
        "subdomains",
        lambda _: (
            {"error": "HttpError"}
            if state["discovery_failure"]
            else {"domains": ["www.example.com", "evil.org", "example.com.evil.org"]}
        ),
    )
    app = await build_app(
        Settings(database_url=clean_db, rules_path=sbr_rules_path),
        enrichers={"tls": static_enricher(ctx, "tls", tls), "subdomains": discovery},
        sinks=[],
    )
    async with app.sessions.begin() as session:
        await repo.upsert_project(session, app.rules)
        root = CertificateMonitor(
            project_id=app.rules.project,
            root_domain="example.com",
            known_domains=["mail.example.com"],
            warn_days=30,
            created_at=now,
            next_check_at=now,
        )
        session.add(root)
        await session.flush()
        monitor_id = root.id
    try:
        yield app, state, monitor_id
    finally:
        await app.close()
        await ctx.http().aclose()


async def alert_count(app: App) -> int:
    async with app.sessions() as session:
        return int(await session.scalar(select(func.count()).select_from(Alert)) or 0)


async def approve_all(app: App, monitor_id: int) -> None:
    async with app.sessions.begin() as session:
        for host in (
            await session.scalars(
                select(MonitoredCertificate).where(
                    MonitoredCertificate.monitor_id == monitor_id,
                )
            )
        ).all():
            host.approved_at = datetime.now(UTC)


async def test_current_certificate_alerts_deduplicate_escalate_renew_and_recover(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, state, monitor_id = world
    assert await certificates.check_monitor(app, monitor_id)
    assert await alert_count(app) == 0  # 包括根域名和人工补充主机，全部等待管理员确认
    await approve_all(app, monitor_id)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 3
    async with app.sessions() as session:
        assert set((await session.scalars(select(Alert.routing))).all()[0]) >= {"domain", "reasons"}
        assert {
            route["domain"] for route in (await session.scalars(select(Alert.routing))).all()
        } == {"example.com", "mail.example.com", "www.example.com"}
    async with app.sessions() as session:
        hosts = (await session.scalars(select(MonitoredCertificate.domain))).all()
        monitor = await session.get(CertificateMonitor, monitor_id)
        assert set(hosts) == {"example.com", "mail.example.com", "www.example.com"}
        assert monitor.scan_started_at is None and monitor.next_check_at > datetime.now(
            UTC
        ) + timedelta(hours=23)
        assert (await session.scalars(select(Entity.type))).all() == ["tls_endpoint"] * 3
    assert not await certificates.check_monitor(app, monitor_id)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 3
    state["end"] = datetime.now(UTC) + timedelta(days=3)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 6
    state["end"] = datetime.now(UTC) - timedelta(days=1)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 9
    state["sha"] = "renewed-but-short"
    state["end"] = datetime.now(UTC) + timedelta(days=2)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 12
    state["sha"] = "renewed"
    state["end"] = datetime.now(UTC) + timedelta(days=90)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    async with app.sessions() as session:
        assert (
            await session.scalar(select(Alert.id).where(Alert.status.in_(["open", "acknowledged"])))
            is None
        )
        assert (await session.scalars(select(Finding.score))).all() == [0] * 3
    state["end"] = datetime.now(UTC) + timedelta(days=20)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 15


async def test_failures_preserve_previous_certificate_and_dedupe(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, state, monitor_id = world
    await certificates.check_monitor(app, monitor_id)
    await approve_all(app, monitor_id)
    await certificates.check_monitor(app, monitor_id, force=True)
    state["failure"] = state["discovery_failure"] = True
    await certificates.check_monitor(app, monitor_id, force=True)
    async with app.sessions() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        assert monitor.error == "HttpError; tls_failed:3"
        assert monitor.next_check_at < datetime.now(UTC) + timedelta(hours=2)
        hosts = (await session.scalars(select(MonitoredCertificate))).all()
        assert all(
            host.state == "error" and host.certificate["sha256"] == "first" for host in hosts
        )
        assert all(host.certificate_checked_at < host.checked_at for host in hosts)
        assert (await session.scalars(select(Alert.status))).all() == ["open"] * 3
    state["failure"] = state["discovery_failure"] = False
    await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 3


async def test_active_lease_and_disabled_monitor_are_skipped(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, _, monitor_id = world
    async with app.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        monitor.scan_started_at = datetime.now(UTC)
    assert not await certificates.check_monitor(app, monitor_id, force=True)
    async with app.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        monitor.scan_started_at = datetime.now(UTC) - timedelta(minutes=16)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    async with app.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        monitor.enabled = False
    assert not await certificates.check_monitor(app, monitor_id, force=True)


async def test_edit_during_scan_discards_old_results(
    world: tuple[App, dict[str, Any], int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _, monitor_id = world
    original = certificates.collect

    async def edit(scan: certificates.Scan, discovery: Any, tls: Any) -> Any:
        async with app.sessions.begin() as session:
            monitor = await session.get(CertificateMonitor, monitor_id)
            monitor.scan_started_at = None
            monitor.warn_days = 1
        return await original(scan, discovery, tls)

    monkeypatch.setattr(certificates, "collect", edit)
    assert not await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 0
    async with app.sessions() as session:
        assert await session.scalar(select(MonitoredCertificate.id)) is None


async def test_overlapping_monitors_do_not_close_each_others_alerts(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, _, monitor_id = world
    await certificates.check_monitor(app, monitor_id)
    await approve_all(app, monitor_id)
    await certificates.check_monitor(app, monitor_id, force=True)
    async with app.sessions.begin() as session:
        now = datetime.now(UTC)
        monitor = CertificateMonitor(
            project_id=app.rules.project,
            root_domain="www.example.com",
            warn_days=7,
            created_at=now,
            next_check_at=now,
        )
        session.add(monitor)
        await session.flush()
        other = monitor.id
    assert await certificates.check_monitor(app, other)
    async with app.sessions() as session:
        assert (
            await session.scalar(
                select(func.count()).select_from(Alert).where(Alert.status == "open")
            )
            == 3
        )


async def test_scan_timeout_marks_unfinished_hosts_without_losing_completed_results(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    current = certificates.policy.current()
    monkeypatch.setattr(
        certificates.policy,
        "_current",
        current.model_copy(
            update={
                "certificates": current.certificates.model_copy(
                    update={"scan_timeout_seconds": 0.02}
                ),
            }
        ),
    )
    ctx = make_context(sbr_rules)
    tls = static_enricher(ctx, "tls", {})

    async def enrich(type_: str, host: str) -> dict[str, Any]:
        if host.startswith("slow"):
            await asyncio.sleep(5)
        return {"present": True, "not_after": (datetime.now(UTC) + timedelta(days=60)).isoformat()}

    monkeypatch.setattr(tls, "enrich", enrich)
    scan = certificates.Scan(
        1, sbr_rules.project, "example.com", 30, ("slow.example.com",), datetime.now(UTC)
    )
    discovery = static_enricher(ctx, "subdomains", {"domains": []})
    try:
        results, problem, _, _ = await certificates.collect(scan, discovery, tls)
        assert results["example.com"]["present"] is True
        assert results["slow.example.com"]["error"] == "scan_timeout"
        assert problem == "tls_failed:1"
    finally:
        await ctx.http().aclose()


async def test_scheduler_queues_due_monitors_once_and_respects_pause_and_lease(
    world: tuple[App, dict[str, Any], int], monkeypatch: pytest.MonkeyPatch
) -> None:
    from opti.pipeline import tasks

    app, _, monitor_id = world

    async def get_app() -> App:
        return app

    queued: list[tuple[int, bool]] = []

    async def queue(id_: int, force: bool) -> None:
        queued.append((id_, force))

    monkeypatch.setattr(tasks, "get_app", get_app)
    monkeypatch.setattr(tasks.check_certificate_monitor, "kiq", queue)
    assert await tasks.check_certificates() == 1
    assert queued == [(monitor_id, False)]
    async with app.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        monitor.scan_started_at = datetime.now(UTC)
    assert await tasks.check_certificates() == 0
    async with app.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        monitor.scan_started_at = None
        monitor.enabled = False
    assert await tasks.check_certificates() == 0


async def test_retry_prioritizes_hosts_unfinished_in_previous_scan(
    world: tuple[App, dict[str, Any], int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _, monitor_id = world
    async with app.sessions.begin() as session:
        session.add(
            MonitoredCertificate(
                monitor_id=monitor_id,
                domain="slow.example.com",
                state="error",
                error="scan_timeout",
            )
        )
    original = certificates.collect

    async def inspect(scan: certificates.Scan, discovery: Any, tls: Any) -> Any:
        assert scan.domains[0] == "slow.example.com"
        return await original(scan, discovery, tls)

    monkeypatch.setattr(certificates, "collect", inspect)
    assert await certificates.check_monitor(app, monitor_id)


async def test_host_failures_alone_retry_next_day(world: tuple[App, dict[str, Any], int]) -> None:
    app, state, monitor_id = world
    state["failure"] = True  # 发现正常，只有主机连不上（例如 CT 历史里已下线的主机）
    assert await certificates.check_monitor(app, monitor_id)
    async with app.sessions() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        assert monitor.error == "tls_failed:3"  # 页面仍提示读取失败的主机数
        assert monitor.next_check_at > datetime.now(UTC) + timedelta(hours=23)
        hosts = (await session.scalars(select(MonitoredCertificate))).all()
        assert all(host.failing_since is not None for host in hosts)
    state["failure"] = False
    assert await certificates.check_monitor(app, monitor_id, force=True)
    async with app.sessions() as session:
        hosts = (await session.scalars(select(MonitoredCertificate))).all()
        assert all(host.failing_since is None for host in hosts)


async def test_scan_timeout_still_retries_within_an_hour(
    world: tuple[App, dict[str, Any], int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _, monitor_id = world

    async def timed_out(scan: certificates.Scan, discovery: Any, tls: Any) -> Any:
        return {"example.com": {"error": "scan_timeout"}}, "tls_failed:1", False, False

    monkeypatch.setattr(certificates, "collect", timed_out)
    assert await certificates.check_monitor(app, monitor_id)
    async with app.sessions() as session:
        monitor = await session.get(CertificateMonitor, monitor_id)
        assert monitor.next_check_at < datetime.now(UTC) + timedelta(hours=2)


async def test_hosts_failing_for_30_days_are_no_longer_checked(
    world: tuple[App, dict[str, Any], int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _, monitor_id = world
    long_ago = datetime.now(UTC) - timedelta(days=31)
    async with app.sessions.begin() as session:
        for domain in ("example.com", "mail.example.com", "www.example.com", "old.example.com"):
            session.add(
                MonitoredCertificate(
                    monitor_id=monitor_id, domain=domain, state="error",
                    error="ConnectError", failing_since=long_ago,
                )
            )  # fmt: skip
    checked: list[str] = []
    original = certificates.collect

    async def spy(scan: certificates.Scan, discovery: Any, tls: Any) -> Any:
        out = await original(scan, discovery, tls)
        checked.extend(out[0])
        return out

    monkeypatch.setattr(certificates, "collect", spy)
    assert await certificates.check_monitor(app, monitor_id)
    # 根域名与手动补充的主机始终检查；CT 仍会返回的 www 与旧主机已停查
    assert sorted(checked) == ["example.com", "mail.example.com"]
    async with app.sessions() as session:
        www = await session.scalar(
            select(MonitoredCertificate).where(MonitoredCertificate.domain == "www.example.com")
        )
        assert www is not None and www.failing_since == long_ago


async def _monitor(app: App, root: str, known: list[str] | None = None) -> int:
    now = datetime.now(UTC)
    async with app.sessions.begin() as session:
        row = CertificateMonitor(
            project_id=app.rules.project,
            root_domain=root,
            known_domains=known or [],
            warn_days=30,
            created_at=now,
            next_check_at=now,
        )
        session.add(row)
        await session.flush()
        return row.id


async def open_alerts(app: App) -> int:
    async with app.sessions() as session:
        return int(
            await session.scalar(
                select(func.count()).select_from(Alert).where(Alert.status == "open")
            )
            or 0
        )


async def test_recreated_monitor_does_not_realert_the_same_certificate(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, state, monitor_id = world
    assert await certificates.check_monitor(app, monitor_id)
    await approve_all(app, monitor_id)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 3
    async with app.sessions.begin() as session:
        await session.delete(await session.get(CertificateMonitor, monitor_id))
    recreated = await _monitor(app, "example.com", ["mail.example.com"])  # 按原样重建
    assert await certificates.check_monitor(app, recreated)
    await approve_all(app, recreated)
    assert await certificates.check_monitor(app, recreated, force=True)
    assert await alert_count(app) == 3  # 同一张证书、同一级别不再重复告警
    # 换证后，删除前留下的未结告警也一并关闭
    state["end"] = datetime.now(UTC) + timedelta(days=200)
    state["sha"] = "renewed"
    assert await certificates.check_monitor(app, recreated, force=True)
    assert await open_alerts(app) == 0


async def test_nested_roots_alert_once_per_host(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, _, monitor_id = world
    assert await certificates.check_monitor(app, monitor_id)
    await approve_all(app, monitor_id)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    nested = await _monitor(app, "www.example.com")
    assert await certificates.check_monitor(app, nested)
    await approve_all(app, nested)
    assert await certificates.check_monitor(app, nested, force=True)
    assert await alert_count(app) == 3  # www.example.com 已在上级根域名的监控里告警过


async def test_only_approved_host_alerts_with_its_own_threshold_and_keeps_approval_after_renewal(
    world: tuple[App, dict[str, Any], int],
) -> None:
    app, state, monitor_id = world
    assert await certificates.check_monitor(app, monitor_id)
    assert await alert_count(app) == 0
    async with app.sessions.begin() as s:
        host = await s.scalar(
            select(MonitoredCertificate).where(MonitoredCertificate.domain == "www.example.com")
        )
        host.approved_at = datetime.now(UTC)
        host.warn_days = 7
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 0  # 根域名默认 30 天，www 单独 7 天，目前剩余 20 天
    state["end"] = datetime.now(UTC) + timedelta(days=3)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 1
    state["sha"] = "renewed"
    state["end"] = datetime.now(UTC) + timedelta(days=2)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 2
    async with app.sessions() as s:
        assert {r["domain"] for r in (await s.scalars(select(Alert.routing))).all()} == {
            "www.example.com"
        }
        host = await s.scalar(
            select(MonitoredCertificate).where(MonitoredCertificate.domain == "www.example.com")
        )
        assert host.approved_at is not None and host.warn_days == 7


async def test_approved_hosts_are_prioritized_and_never_retired(
    world: tuple[App, dict[str, Any], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, monitor_id = world
    assert await certificates.check_monitor(app, monitor_id)
    async with app.sessions.begin() as s:
        host = await s.scalar(
            select(MonitoredCertificate).where(MonitoredCertificate.domain == "www.example.com")
        )
        host.approved_at = datetime.now(UTC)
        host.failing_since = datetime.now(UTC) - timedelta(days=31)
    original = certificates.collect

    async def inspect(scan: certificates.Scan, discovery: Any, tls: Any) -> Any:
        assert scan.domains[0] == "www.example.com"
        assert "www.example.com" not in scan.retired
        return await original(scan, discovery, tls)

    monkeypatch.setattr(certificates, "collect", inspect)
    assert await certificates.check_monitor(app, monitor_id, force=True)
    assert await alert_count(app) == 1
