import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.cursors import save_cursors
from opti.db.models import ConnectorRun
from opti.gateway.dispatch import (
    RemoteEnricher,
    dispatch_connector_run,
    remote_enricher,
    sweep_stale_runs,
)
from opti.gateway.jobs import MemoryJobQueue
from opti.pipeline.app import build_app
from opti.sdk.base import Enricher
from opti.sdk.registry import Registry
from opti.sdk.scan import KeywordScan
from opti.settings import Settings

REPO = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


@pytest.mark.db
async def test_manual_scan_sends_selected_word_and_sanitized_rules_snapshot(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    jobs = MemoryJobQueue()
    scan = KeywordScan(
        project_id=sbr_rules.project, rules_version=3, scope="text", term="Sample Brand"
    )
    assert await dispatch_connector_run(
        session, jobs, "google_news", now=NOW, scan=scan, rules=sbr_rules
    )
    job = await jobs.lease("hk1", wait=1)
    assert job is not None
    payload = job.payload["keyword_scan"]
    assert payload["scan"] == scan.model_dump(mode="json")
    assert payload["rules"]["project"] == sbr_rules.project
    assert all(s["type"] != "executive" for s in payload["rules"]["sets"].values())


def _dns_class() -> type[Enricher]:
    cls = Registry().load_class("dns")
    assert issubclass(cls, Enricher)
    return cls


async def test_remote_enricher_round_trip() -> None:
    jobs = MemoryJobQueue()
    remote = remote_enricher(_dns_class(), jobs, timeout=5)

    async def node() -> None:
        job = await jobs.lease("hk1", wait=2)
        assert job is not None and job.kind == "enrich"
        assert job.payload == {"enricher": "dns", "type": "domain", "value": "sbr-loans.com"}
        await jobs.complete(job.id, "hk1", {"exists": True, "a": ["203.0.113.5"]})

    task = asyncio.create_task(node())
    assert await remote.enrich("domain", "sbr-loans.com") == {"exists": True, "a": ["203.0.113.5"]}
    await task


async def test_remote_enricher_times_out() -> None:
    remote = remote_enricher(_dns_class(), MemoryJobQueue(), timeout=0.2)
    assert await remote.enrich("domain", "sbr-loans.com") == {"error": "RemoteTimeout"}


def test_remote_enricher_keeps_class_metadata() -> None:
    cls = _dns_class()
    remote = remote_enricher(cls, MemoryJobQueue(), timeout=5)
    assert isinstance(remote, RemoteEnricher)
    assert remote.id == "dns" and remote.supports("domain") and not remote.supports("ip")
    assert remote.cache_ttl_seconds == cls.cache_ttl_seconds


async def test_remote_mode_wraps_only_overseas_enrichers(
    sbr_rules_path: Path, tmp_path: Path
) -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://u:p@127.0.0.1:1/none",  # 不会真正连接
        collector_mode="remote", rules_path=sbr_rules_path,
        config_dir=REPO / "config" / "connectors", state_dir=tmp_path,
        alerting_config=tmp_path / "alerting.yaml",
    )  # fmt: skip
    jobs = MemoryJobQueue()
    app = await build_app(settings, sinks=[], jobs=jobs)
    try:
        assert app.jobs is jobs
        for eid in ("dns", "http_probe", "tls", "subdomains"):  # egress: overseas
            assert isinstance(app.enrichment.get(eid), RemoteEnricher), eid
        for eid in ("rdap", "tranco"):  # egress: any，在境内运行
            e = app.enrichment.get(eid)
            assert e is not None and not isinstance(e, RemoteEnricher), eid
    finally:
        await app.close()


@pytest.mark.db
async def test_dispatch_creates_run_and_job_with_cursors(session: AsyncSession) -> None:
    await save_cursors(session, "crtsh", {"q:sbr": "41"}, NOW)
    jobs = MemoryJobQueue()
    run_id = await dispatch_connector_run(session, jobs, "crtsh", now=NOW, max_runtime=600)
    assert run_id is not None
    run = await session.get(ConnectorRun, run_id)
    assert run is not None and run.status == "dispatched"
    assert run.deadline_at == NOW + timedelta(seconds=600)
    job = await jobs.lease("hk1", wait=1)
    assert job is not None and job.kind == "run_connector" and not job.reply
    assert job.payload["run_id"] == run_id and job.payload["cursors"] == {"q:sbr": "41"}


@pytest.mark.db
async def test_dispatch_skips_when_previous_run_active(session: AsyncSession) -> None:
    jobs = MemoryJobQueue()
    assert await dispatch_connector_run(session, jobs, "crtsh", now=NOW) is not None
    assert await dispatch_connector_run(session, jobs, "crtsh", now=NOW) is None
    assert await dispatch_connector_run(session, jobs, "nrd", now=NOW) is not None


@pytest.mark.db
async def test_sweep_fails_overdue_runs(session: AsyncSession) -> None:
    jobs = MemoryJobQueue()
    overdue = await dispatch_connector_run(session, jobs, "crtsh", now=NOW, max_runtime=60)
    fresh = await dispatch_connector_run(session, jobs, "nrd", now=NOW, max_runtime=3600)
    local = ConnectorRun(
        connector_id="dnstwist", started_at=NOW, status="running", items=0, errors=0, message=""
    )
    session.add(local)  # 本机运行没有 deadline_at，不受影响
    await session.flush()
    assert await sweep_stale_runs(session, NOW + timedelta(minutes=5)) == 1
    for run_id, status in ((overdue, "error"), (fresh, "dispatched"), (local.id, "running")):
        run = await session.get(ConnectorRun, run_id, populate_existing=True)
        assert run is not None and run.status == status
    # 失败后可以重新下发
    assert (
        await dispatch_connector_run(session, jobs, "crtsh", now=NOW + timedelta(minutes=6))
        is not None
    )


@pytest.mark.db
async def test_late_result_cannot_overwrite_newer_cursor(session: AsyncSession) -> None:
    from opti.gateway.records import finish_dispatched_run

    jobs = MemoryJobQueue()
    old = await dispatch_connector_run(session, jobs, "crtsh", now=NOW, max_runtime=60)
    assert old is not None
    await sweep_stale_runs(session, NOW + timedelta(minutes=5))
    await save_cursors(session, "crtsh", {"q": "newer"}, NOW)
    assert not await finish_dispatched_run(
        session, old, {"status": "ok", "cursors": {"q": "older"}}, NOW
    )
    from opti.db.cursors import PgCursorStore

    cursors = PgCursorStore()
    await cursors.load(session, "crtsh")
    assert cursors.get("crtsh", "q") == "newer"


async def test_remote_url_enricher_keeps_url_target() -> None:
    from opti.enrichers.screenshot.enricher import ScreenshotEnricher

    jobs = MemoryJobQueue()
    remote = remote_enricher(ScreenshotEnricher, jobs, timeout=5)
    url = "https://sites.google.com/view/sbr-grants"
    assert remote.supports("url")

    async def node() -> None:
        job = await jobs.lease("hk1", wait=2)
        assert job is not None
        assert job.payload == {"enricher": "screenshot", "type": "url", "value": url}
        await jobs.complete(job.id, "hk1", {"final_url": url, "artifacts": []})

    task = asyncio.create_task(node())
    assert (await remote.enrich("url", url))["final_url"] == url
    await task
