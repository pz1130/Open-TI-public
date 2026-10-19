from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy import func, select, update

from opti.configs.testing import override
from opti.core.config import load_project_rules
from opti.core.documents import document_payload, parse_document
from opti.core.exposure import breach_catalog, exposure_payload
from opti.core.kev import SoftwareList
from opti.core.scoring import Category, Score, Severity
from opti.core.vendors import VendorList
from opti.db import repo
from opti.db.models import (
    Adjudication,
    Alert,
    AlertFinding,
    AppUser,
    AuditLog,
    Campaign,
    CodeRepo,
    ConnectorCursor,
    ConnectorRun,
    Document,
    DomainObservation,
    Entity,
    Evidence,
    ExposedAccount,
    Finding,
    KevEntry,
    LeakPost,
    Report,
    Takedown,
    WatchedDomain,
)
from opti.gateway.jobs import MemoryJobQueue
from opti.pipeline import documents
from opti.pipeline.app import App, build_app, run_connector_once, set_app
from opti.pipeline.broker import broker
from opti.pipeline.schedule import ManifestScheduleSource
from opti.pipeline.tasks import (
    adjudicate_pending,
    apply_retention,
    daily_report,
    dispatch_pending,
    enrich_hosting,
    ingest,
    maintain_partitions,
    monthly_report,
    push_exposures,
    push_tickets,
    recheck_watched_domain,
    recheck_watchlist,
    recompute_campaigns,
    rematch_kev,
    rematch_leak_posts,
    run_connector,
    scan_code_repos,
    takedown_reminders,
    weekly_report,
)
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.models import RawItem, raw_item_to_dict
from opti.sdk.registry import Registry
from opti.sdk.runtime import RuntimePaths
from opti.sdk.scan import KeywordScan
from opti.sdk.testing import make_context, static_enricher
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore
from opti.tickets.client import PushResult
from opti.tickets.config import TicketsConfig

pytestmark = pytest.mark.db
REPO = Path(__file__).resolve().parents[2]
PROJECT = "sample-brand-protection"
PHISH = {"reachable": True, "status": 200, "title": "Sample Brand Login",
         "has_password_field": True, "brand_terms": ["Sample Brand"]}  # fmt: skip


async def test_inventory_update_rebuilds_processor(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, _ = app
    before = application.processor
    override(
        application.config,
        vendors=VendorList.model_validate(
            {
                "vendors": [
                    {
                        "id": "acme",
                        "name": "Acme Cloud",
                        "domains": ["acme.example"],
                        "tier": "critical",
                    }
                ],
            }
        ),
    )
    after = application.processor
    assert after is not before
    override(
        application.config,
        software=SoftwareList.model_validate(
            {
                "software": [{"id": "vpn", "vendor": "Fortinet", "products": ["FortiOS"]}],
            }
        ),
    )
    assert application.processor is not after
    assert application.processor.software is not None


async def test_rematch_refreshes_before_matching(
    app: tuple[App, FakeSink, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    application, _, _ = app
    refreshed: list[bool] = []
    original = application.config.refresh

    async def spy() -> bool:
        refreshed.append(True)
        return await original()

    monkeypatch.setattr(application.config, "refresh", spy)
    assert (await (await rematch_kev.kiq()).wait_result()).return_value == 0
    assert refreshed == [True]
    async with application.sessions() as session:
        row = (
            await session.execute(
                select(AuditLog.action, AuditLog.detail).where(AuditLog.target_id == "software")
            )
        ).one()
    assert row[0] == "config.rematched" and row[1]["alerts"] == 0 and "version" in row[1]


PARKED = {"reachable": True, "status": 200, "title": "for sale", "has_password_field": False,
          "brand_terms": []}  # fmt: skip
SCAN_STATE: dict[str, Any] = {}


class FakeSink:
    name = "fake"

    def __init__(self) -> None:
        self.alerts: list[Any] = []
        self.notices: list[Any] = []
        self.reports: list[Any] = []

    async def send_alert(self, view: Any) -> None:
        self.alerts.append(view)

    async def send_notice(self, notice: Any) -> None:
        self.notices.append(notice)

    async def send_report(self, report: Any) -> None:
        self.reports.append(report)


async def test_adjudicate_pending_releases_queue_when_disabled(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, _ = app
    async with application.sessions() as s:
        assert await application.llm.cfg(s) is None
    now = datetime.now(UTC)
    async with application.sessions() as s, s.begin():
        await repo.upsert_project(s, application.rules)
        entity = await repo.upsert_entity(s, "document", "cluster:1", now)
        score = Score(50, Severity.MEDIUM, Category.NEGATIVE_PRESS, {"base": 50})
        up = await repo.upsert_finding(
            s,
            project_id=application.rules.project,
            entity=entity,
            score=score,
            match={"document": {"title": "t"}},
            source="rss",
            now=now,
        )
        s.add(
            Adjudication(
                finding_id=up.finding.id,
                status="pending",
                held_severity="medium",
                attempts=0,
                created_at=now,
                updated_at=now,
            )
        )
    assert (await (await adjudicate_pending.kiq()).wait_result()).return_value == 1


async def test_daily_report_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, sink, _ = app
    now = datetime.now(UTC)
    async with application.sessions() as s, s.begin():
        await repo.upsert_project(s, application.rules)
        entity = await repo.upsert_entity(s, "domain", "sbr-portal.top", now)
        score = Score(50, Severity.MEDIUM, Category.TYPOSQUAT_DOMAIN, {"base": 50})
        up = await repo.upsert_finding(
            s,
            project_id=application.rules.project,
            entity=entity,
            score=score,
            match={},
            source="test",
            now=now,
        )
        alert_id = (await repo.open_alert(s, up.finding, Severity.MEDIUM, now)).id
    rid = (await (await daily_report.kiq()).wait_result()).return_value
    assert sink.reports and sink.reports[-1].report_id == rid
    async with application.sessions() as s:
        alert, report = await s.get(Alert, alert_id), await s.get(Report, rid)
        assert alert is not None and alert.digest_sent_at is not None
        assert report is not None and report.sent_at is not None and report.sent_sinks == ["fake"]
    assert (await (await weekly_report.kiq()).wait_result()).return_value != rid
    monthly = (await (await monthly_report.kiq()).wait_result()).return_value
    assert sink.reports[-1].report_id == monthly and sink.reports[-1].kind == "monthly"
    # 每天检查一次：同一月份只生成一份
    assert (await (await monthly_report.kiq()).wait_result()).return_value == monthly


def test_monthly_report_checks_daily() -> None:
    assert monthly_report.labels.get("schedule") == [{"cron": "10 1 * * *"}]


ECHO = {
    "id": "echo", "name": "Echo", "version": "0.1.0", "category": "ct", "kind": ["poll"],
    "tier": "free", "entrypoint": "opti.sdk.testing:EchoConnector",
    "schedule": {"default": "*/5 * * * *"},
    "config_schema": {"type": "object", "properties": {"items": {"type": "array", "default": []}}},
}  # fmt: skip


@pytest.fixture
async def app(
    clean_db: str, sbr_rules_path: Path, tmp_path: Path
) -> AsyncIterator[tuple[App, FakeSink, dict[str, Any]]]:
    root = tmp_path / "connectors"
    (root / "echo").mkdir(parents=True)
    (root / "echo" / "connector.yaml").write_text(yaml.safe_dump(ECHO))
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "echo.yaml").write_text(
        yaml.safe_dump({"enabled": True, "license_approved": True,
                        "config": {"items": [{"matches": [{"domain": "sbr-loans.com"}]}, {"x": 1}]}})
    )  # fmt: skip
    rules = load_project_rules(sbr_rules_path)
    ctx = make_context(rules)
    http_state = dict(PHISH)
    enrichers = {
        "ip_rdap": static_enricher(
            ctx, "ip_rdap", {"found": True, "network_name": "TEST-NET"}, types=("ip",)
        ),
        "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "mx": []}),
        "rdap": static_enricher(ctx, "rdap", {"registration": "2026-09-30T00:00:00Z"}),
        "tranco": static_enricher(ctx, "tranco", {"rank": None}),
        "http_probe": static_enricher(ctx, "http_probe", lambda _v: dict(http_state)),
        "tls": static_enricher(ctx, "tls", {"present": False}),
        "secret_scan": static_enricher(
            ctx, "secret_scan", lambda _v: dict(SCAN_STATE), types=("repo",)
        ),
    }
    sink = FakeSink()
    settings = Settings(
        database_url=clean_db, rules_path=sbr_rules_path, config_dir=cfg,
        state_dir=tmp_path / "data", alerting_config=tmp_path / "alerting.yaml",
    )  # fmt: skip
    application = await build_app(
        settings, enrichers=enrichers, sinks=[sink], registry=Registry([root])
    )
    set_app(application)
    await broker.startup()
    yield application, sink, http_state
    await broker.shutdown()
    set_app(None)
    await application.close()


def _item_dict(domain: str) -> dict[str, Any]:
    return {
        "connector_id": "certstream", "source_item_id": "p1", "fetched_at": "2026-10-02T08:00:00+00:00",
        "url": None, "payload": {"matches": [{"domain": domain}]}, "project_ids": [PROJECT],
    }  # fmt: skip


async def test_ingest_creates_alert_and_dispatches(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, sink, _ = app
    task = await ingest.kiq(_item_dict("sbr-loans.com"))
    result = await task.wait_result()
    assert result.return_value["alerts"]
    assert [v.domain for v in sink.alerts] == ["sbr-loans.com"]
    async with application.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(Alert)) == 1


async def test_run_connector_once(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    queued: list[RawItem] = []

    async def enqueue(item: RawItem) -> None:
        queued.append(item)

    assert await run_connector_once(application, "echo", enqueue=enqueue) == 2
    assert len(queued) == 2
    async with application.sessions() as s:
        cursor = await s.scalar(
            select(ConnectorCursor.value).where(ConnectorCursor.connector_id == "echo")
        )
        run = await s.scalar(select(ConnectorRun))
    assert cursor == "1"
    assert run is not None and run.status == "ok" and run.items == 2


async def test_selected_keyword_task_and_stale_project_guard(
    app: tuple[App, FakeSink, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from opti.pipeline import tasks

    application, _, _ = app
    manifest = application.registry.manifest("echo").model_copy(update={"search_inputs": ("text",)})
    original = application.registry.manifest
    monkeypatch.setattr(
        application.registry, "manifest", lambda cid: manifest if cid == "echo" else original(cid)
    )
    seen = []

    async def run(*args: Any, **kwargs: Any) -> int:
        seen.append(kwargs["scan"])
        return 2

    monkeypatch.setattr(tasks, "run_connector_once", run)
    spec = KeywordScan(
        project_id=application.rules.project,
        rules_version=application.config.snapshot.version("rules"),
        scope="text",
        term="Sample Brand",
    )
    assert await tasks.scan_keywords("echo", spec.model_dump(mode="json")) == 2
    assert seen == [spec]
    stale = spec.model_copy(update={"project_id": "old-project"})
    assert await tasks.scan_keywords("echo", stale.model_dump(mode="json")) is None
    assert len(seen) == 1


async def test_recheck_watchlist_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, sink, http_state = app
    http_state.clear()
    http_state.update(PARKED)
    await ingest.kiq(_item_dict("sbr-loans.com"))
    async with application.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(WatchedDomain)) == 1
    http_state.clear()
    http_state.update(PHISH)
    assert await recheck_watchlist() == 1
    assert [v.severity for v in sink.alerts] == ["critical"]


async def test_inactive_watch_does_not_starve_active_project(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, _ = app
    from opti.pipeline.watchlist import ensure_watched

    now = datetime.now(UTC)
    async with application.sessions.begin() as s:
        other = application.rules.model_copy(update={"project": "inactive"})
        await repo.upsert_project(s, application.rules)
        await repo.upsert_project(s, other)
        await ensure_watched(
            s, other.project, "sbr-inactive.com", reason="test", now=now - timedelta(days=2)
        )
        await ensure_watched(
            s,
            application.rules.project,
            "sbr-active.com",
            reason="test",
            now=now - timedelta(days=1),
        )
        old_id = await s.scalar(
            select(WatchedDomain.id).where(WatchedDomain.project_id == other.project)
        )
        active_id = await s.scalar(
            select(WatchedDomain.id).where(WatchedDomain.project_id == application.rules.project)
        )
    assert await recheck_watchlist(limit=1) == 1
    async with application.sessions() as s:
        assert (await s.get(WatchedDomain, old_id)).last_checked_at is None
        assert (await s.get(WatchedDomain, active_id)).last_checked_at is not None


async def test_manual_recheck_targets_one_domain_even_when_not_due(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, http_state = app
    http_state.clear()
    http_state.update(PARKED)
    await ingest.kiq(_item_dict("sbr-loans.com"))
    async with application.sessions() as s:
        watched = (await s.scalars(select(WatchedDomain))).one()
        watch_id = watched.id
        assert watched.last_checked_at is None
    assert await recheck_watched_domain(watch_id, None)
    async with application.sessions() as s:
        checked = (await s.get(WatchedDomain, watch_id)).last_checked_at
        assert checked is not None
        assert await s.scalar(select(func.count()).select_from(DomainObservation)) == 1
    assert not await recheck_watched_domain(watch_id, None)
    assert await recheck_watched_domain(watch_id, checked.isoformat())
    async with application.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(DomainObservation)) == 2


async def test_recheck_and_new_observation_do_not_deadlock(
    app: tuple[App, FakeSink, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    application, _, http_state = app
    http_state.clear()
    http_state.update(PARKED)
    now = datetime.now(UTC)
    async with application.sessions.begin() as session:
        await application.processor.process(
            session,
            RawItem(
                "certstream",
                "first",
                now,
                None,
                {"matches": [{"domain": "sbr-loans.com"}]},
                project_ids=(PROJECT,),
            ),
        )
    http_state.clear()
    http_state.update(PHISH)
    entered, release = asyncio.Event(), asyncio.Event()
    original = application.enrichment.enrich

    async def paused(entity: Entity, ids: Any, *, force: bool = False, targets: Any = None) -> Any:
        if force and entity.value == "sbr-loans.com":
            entered.set()
            await release.wait()
        return await original(entity, ids, force=force, targets=targets)

    monkeypatch.setattr(application.enrichment, "enrich", paused)
    recheck = asyncio.create_task(recheck_watchlist())
    await asyncio.wait_for(entered.wait(), timeout=5)

    async def observe() -> None:
        async with application.sessions.begin() as session:
            await application.processor.process(
                session,
                RawItem(
                    "certstream",
                    "second",
                    now,
                    None,
                    {"matches": [{"domain": "sbr-loans.com"}]},
                    project_ids=(PROJECT,),
                ),
            )

    incoming = asyncio.create_task(observe())
    await asyncio.sleep(0.05)
    release.set()
    assert await asyncio.wait_for(recheck, timeout=10) == 1
    await asyncio.wait_for(incoming, timeout=10)


async def test_maintain_partitions(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    out = await maintain_partitions()
    assert set(out) == {"created", "dropped"}


def test_dispatch_pending_schedule() -> None:
    schedules = dispatch_pending.labels.get("schedule", [])
    assert {"cron": "*/5 * * * *"} in schedules


async def test_run_failure_finishes_error_and_closes_client(
    app: tuple[App, FakeSink, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    application, _, _ = app
    closed: list[RateLimitedHttpClient] = []
    original = RateLimitedHttpClient.aclose

    async def spy(self: RateLimitedHttpClient) -> None:
        await original(self)
        closed.append(self)
        raise RuntimeError("close failed")

    monkeypatch.setattr(RateLimitedHttpClient, "aclose", spy)

    async def enqueue(_item: RawItem) -> None:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_connector_once(application, "echo", enqueue=enqueue)

    assert len(closed) == 1 and closed[0]._client.is_closed
    async with application.sessions() as s:
        run = await s.scalar(select(ConnectorRun))
    assert run is not None and run.status == "error" and run.message == "CancelledError"
    assert run.ended_at is not None


async def test_manifest_schedule_source() -> None:
    source = ManifestScheduleSource(
        Registry(), RuntimePaths(config_dir=REPO / "config" / "connectors")
    )
    schedules = {s.args[0]: s.cron for s in await source.get_schedules()}
    assert schedules["crtsh"] == "0 */6 * * *" and "dnstwist" in schedules
    assert "nrd" not in schedules  # 法务未批准
    assert "certstream" not in schedules and "dns" not in schedules  # 流式连接器与富化器不定时运行


async def test_ingest_is_retried_after_transient_error(
    app: tuple[App, FakeSink, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """任务出错时消息已确认；ingest 幂等，必须自动重试，否则这条命中就丢了。"""
    application, sink, _ = app
    original = application.processor.process
    calls: list[int] = []

    async def flaky(session: Any, item: RawItem) -> Any:
        calls.append(1)
        if len(calls) == 1:
            raise TimeoutError("QueuePool limit reached")
        return await original(session, item)

    monkeypatch.setattr(application.processor, "process", flaky)
    await ingest.kiq(_item_dict("sbr-loans.com"))
    assert len(calls) == 2
    assert [v.domain for v in sink.alerts] == ["sbr-loans.com"]


async def test_run_connector_is_dispatched_in_remote_mode(
    clean_db: str, sbr_rules_path: Path, tmp_path: Path
) -> None:
    root = tmp_path / "connectors"
    (root / "echo").mkdir(parents=True)
    (root / "echo" / "connector.yaml").write_text(
        yaml.safe_dump(ECHO)
    )  # 未声明 egress，默认 overseas
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "echo.yaml").write_text(yaml.safe_dump({"enabled": True, "license_approved": True}))
    jobs = MemoryJobQueue()
    settings = Settings(
        database_url=clean_db, rules_path=sbr_rules_path, config_dir=cfg, state_dir=tmp_path,
        alerting_config=tmp_path / "alerting.yaml", collector_mode="remote",
    )  # fmt: skip
    application = await build_app(
        settings, enrichers={}, sinks=[], registry=Registry([root]), jobs=jobs
    )
    set_app(application)
    await broker.startup()
    try:
        task = await run_connector.kiq("echo")
        run_id = (await task.wait_result()).return_value
        assert isinstance(run_id, int)
        job = await jobs.lease("hk1", wait=1)
        assert job is not None and job.payload["connector_id"] == "echo"
    finally:
        await broker.shutdown()
        set_app(None)
        await application.close()


async def test_ingest_triggers_evidence_capture(
    clean_db: str, sbr_rules_path: Path, tmp_path: Path
) -> None:
    rules = load_project_rules(sbr_rules_path)
    ctx = make_context(rules)
    shot = {"final_url": "https://sbr-loans.com/", "captured_at": "2026-10-02T08:01:00+00:00",
            "method": "opti-sandbox/test",
            "artifacts": [{"name": "screenshot", "content_type": "image/png", "data_b64": "iVBORw0KGgo="}]}  # fmt: skip
    enrichers = {
        "ip_rdap": static_enricher(
            ctx, "ip_rdap", {"found": True, "network_name": "TEST-NET"}, types=("ip",)
        ),
        "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "mx": []}),
        "rdap": static_enricher(ctx, "rdap", {"registration": "2026-09-30T00:00:00Z"}),
        "tranco": static_enricher(ctx, "tranco", {"rank": None}),
        "http_probe": static_enricher(ctx, "http_probe", dict(PHISH)),
        "screenshot": static_enricher(ctx, "screenshot", shot, ttl=0),
    }
    store = MemoryObjectStore()
    settings = Settings(
        database_url=clean_db, rules_path=sbr_rules_path, config_dir=tmp_path,
        state_dir=tmp_path, alerting_config=tmp_path / "alerting.yaml",
    )  # fmt: skip
    application = await build_app(settings, enrichers=enrichers, sinks=[FakeSink()], store=store)
    set_app(application)
    await broker.startup()
    try:
        await ingest.kiq(_item_dict("sbr-loans.com"))
        async with application.sessions() as s:
            rows = (await s.scalars(select(Evidence))).all()
            assert [r.kind for r in rows] == ["screenshot"]
            assert rows[0].object_key in store.objects
            alert = await s.scalar(select(Alert))
            assert alert is not None and alert.evidence_status == "done"
    finally:
        await broker.shutdown()
        set_app(None)
        await application.close()


async def test_enrich_hosting_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    await (await ingest.kiq(_item_dict("sbr-loans.com"))).wait_result()
    result = await (await enrich_hosting.kiq()).wait_result()
    assert result.return_value == 1
    async with application.sessions() as s:
        ip = await s.scalar(
            select(Entity).where(Entity.type == "ip", Entity.value == "203.0.113.5")
        )
        assert ip is not None and ip.enrichment["ip_rdap"]["data"]["network_name"] == "TEST-NET"


async def test_takedown_reminders_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, sink, _ = app
    await (await ingest.kiq(_item_dict("sbr-loans.com"))).wait_result()
    past = datetime.now(UTC) - timedelta(days=5)
    async with application.sessions() as s, s.begin():
        alert = await s.scalar(select(Alert))
        user = AppUser(username="alice", password_hash="!", roles=["analyst"], created_at=past)
        s.add(user)
        await s.flush()
        s.add(
            Takedown(
                project_id=PROJECT, alert_id=alert.id, finding_id=(await s.scalar(select(AlertFinding.finding_id))),
                domain="sbr-loans.com", target={"kind": "registrar", "id": "registrar:x", "name": "X Registrar"},
                language="en-US", subject="s", body="b", state="submitted", created_by=user.id,
                created_at=past, updated_at=past, submitted_at=past, due_at=past + timedelta(hours=72),
            )
        )  # fmt: skip
    result = await (await takedown_reminders.kiq()).wait_result()
    assert result.return_value == 1 and sink.notices[0].title.startswith("下架投诉 #")
    async with application.sessions() as s:
        td = await s.scalar(select(Takedown))
        assert td is not None and td.reminders == 1


class FakeTickets:
    name = "fake"

    def __init__(self) -> None:
        self.pushed: list[Any] = []
        self.extras: list[Any] = []

    async def push(
        self,
        view: Any,
        extra: Any = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        self.pushed.append(view)
        self.extras.append(extra)
        return PushResult("INC001", self.name)


async def test_push_tickets_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    fake = FakeTickets()
    application.tickets = fake
    override(
        application.config,
        tickets=TicketsConfig(enabled=True, auto_push=(Severity.CRITICAL, Severity.HIGH)),
    )
    await (await ingest.kiq(_item_dict("sbr-loans.com"))).wait_result()  # 产生告警时立即触发推送
    assert len(fake.pushed) == 1
    assert (await (await push_tickets.kiq()).wait_result()).return_value == 0  # 已推送的不再推送
    async with application.sessions() as s:
        alert = await s.scalar(select(Alert))
        assert (
            alert is not None
            and alert.ticket_ref == "INC001"
            and alert.ticket_pushed_at is not None
        )


def _exposure_item(accounts: list[str]) -> dict[str, Any]:
    info = breach_catalog([{"Name": "NewLeak", "Title": "New Leak", "BreachDate": "2026-08-01",
                            "DataClasses": ["Passwords"], "IsVerified": True}])["NewLeak"]  # fmt: skip
    item = RawItem(
        connector_id="hibp", source_item_id="x1", fetched_at=datetime.now(UTC), url=None, project_ids=(PROJECT,),
        payload=exposure_payload(source="hibp", kind="breach", key="hibp:sbr.int:NewLeak", domain="sbr.int",
                                 info=info, title=info.title, affected=len(accounts), accounts=accounts),
    )  # fmt: skip
    return raw_item_to_dict(item)


async def test_push_exposures_and_purge(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    fake = FakeTickets()
    application.tickets = fake
    override(
        application.config,
        tickets=TicketsConfig(enabled=True, auto_push=(Severity.CRITICAL, Severity.HIGH)),
    )
    await (await ingest.kiq(_exposure_item(["a@sbr.int", "b@sbr.int"]))).wait_result()
    # 通用工单推送跳过凭据暴露告警，只由暴露推送建一张带账户的工单
    assert len(fake.pushed) == 1 and fake.extras[0]["exposure"]["accounts"] == [
        "a@sbr.int",
        "b@sbr.int",
    ]
    assert (await (await push_exposures.kiq()).wait_result()).return_value == 0
    async with application.sessions() as s, s.begin():
        await s.execute(
            update(ExposedAccount).values(last_seen=datetime.now(UTC) - timedelta(days=400))
        )
    assert (await (await apply_retention.kiq()).wait_result()).return_value["exposed_accounts"] == 2


async def test_rematch_task_uses_repository_vendor_list(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, sink, _ = app
    now = datetime.now(UTC)
    async with application.sessions() as s, s.begin():
        s.add(LeakPost(key="akira:example cloud services", group_name="akira", victim="Example Cloud Services Ltd",
                       discovered=now - timedelta(days=2), sources=["ransomware_live"], first_seen=now, last_seen=now))  # fmt: skip
    result = await (await rematch_leak_posts.kiq()).wait_result()
    assert result.return_value == 1  # config/vendors.yaml 示例中的 critical 供应商
    assert sink.alerts and sink.alerts[-1].category == "ransomware_mention"


def _code_hit_item() -> dict[str, Any]:
    hit = {"repo": "dev2/deploy", "path": "config/app.env",
           "html_url": "https://github.com/dev2/deploy/blob/main/config/app.env",
           "blob_sha": "s1", "term": "sbr.int", "term_kind": "domain", "fork": False,
           "fragments": []}  # fmt: skip
    return raw_item_to_dict(
        RawItem(
            connector_id="github_code",
            source_item_id="dev2/deploy:config/app.env:s1",
            fetched_at=datetime.now(UTC),
            url=hit["html_url"],
            payload={"code_hit": hit},
            project_ids=(PROJECT,),
        )
    )


async def test_scan_code_repos(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, sink, _ = app
    await (await ingest.kiq(_code_hit_item())).wait_result()
    SCAN_STATE.clear()
    SCAN_STATE.update({"supported": True, "scanned": True, "commit": "a" * 40, "total": 1,
                       "secrets": [{"rule": "aws-access-token", "file": "config/app.env", "line": 2,
                                    "commit": "c" * 40, "date": datetime.now(UTC).isoformat(),
                                    "prefix": "AKIA", "fingerprint": "f" * 64, "length": 20, "url": "u"}]})  # fmt: skip
    assert (await (await scan_code_repos.kiq()).wait_result()).return_value == 1
    assert sink.alerts[-1].category == "secret_leak" and sink.alerts[-1].severity == "critical"
    async with application.sessions() as session:
        row = (await session.scalars(select(CodeRepo))).one()
        assert row.scan_status == "ok" and row.next_scan_at > datetime.now(UTC) + timedelta(days=29)
    assert (await (await scan_code_repos.kiq()).wait_result()).return_value == 0


async def test_scan_failure_keeps_previous_result(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, _ = app
    await (await ingest.kiq(_code_hit_item())).wait_result()
    SCAN_STATE.clear()
    SCAN_STATE.update({"supported": True, "scanned": False, "error": "clone_timeout"})
    assert (await (await scan_code_repos.kiq()).wait_result()).return_value == 1
    async with application.sessions() as session:
        row = (await session.scalars(select(CodeRepo))).one()
        assert row.scan_status == "error:clone_timeout" and row.last_scanned_at is None
        assert timedelta(hours=23) < row.next_scan_at - datetime.now(UTC) <= timedelta(days=1)
        finding = (await session.scalars(select(Finding))).one()
        assert finding.match["scan"] is None and finding.category == "data_leak"


async def test_retention_purges_documents(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    now = datetime.now(UTC)
    async with application.sessions() as session, session.begin():
        old = parse_document(document_payload(url="https://news.example/old", title="Old article"))
        fresh = parse_document(
            document_payload(url="https://news.example/new", title="New article")
        )
        await documents.upsert(
            session, old, contexts=[], connector="rss", now=now - timedelta(days=400)
        )
        await documents.upsert(session, fresh, contexts=[], connector="rss", now=now)
    assert (await (await apply_retention.kiq()).wait_result()).return_value["documents"] == 1
    async with application.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(Document)) == 1


async def test_rematch_kev_task_uses_configured_inventory(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, _ = app
    software = application.processor.software
    assert software is not None and software.empty  # 仓库自带空清单
    now = datetime.now(UTC)
    async with application.sessions() as s, s.begin():
        s.add(KevEntry(cve_id="CVE-2026-0001", vendor="Example Networks", product="EdgeGate VPN",
                       date_added=date(2026, 10, 1), first_seen=now, last_seen=now))  # fmt: skip
    result = await (await rematch_kev.kiq()).wait_result()
    assert result.return_value == 0


async def test_apply_retention_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    old = datetime.now(UTC) - timedelta(days=200)
    async with application.sessions() as s, s.begin():
        s.add(ConnectorRun(connector_id="crtsh", started_at=old, ended_at=old, status="ok", items=0, errors=0,
                           message=""))  # fmt: skip
    result = (await (await apply_retention.kiq()).wait_result()).return_value
    assert result["connector_runs"] == 1 and result["evidence_files"] == 0
    async with application.sessions() as s:
        log = (await s.scalars(select(AuditLog).where(AuditLog.action == "retention.purge"))).one()
    assert log.actor == "system:retention" and log.detail["connector_runs"] == 1


async def test_app_enrichment_never_visits_platform_pages(
    app: tuple[App, FakeSink, dict[str, Any]],
) -> None:
    application, _, _ = app
    assert not application.enrichment.visit_allowed("url", "https://www.linkedin.com/in/fake-ceo/")
    assert not application.enrichment.visit_allowed("domain", "t.me")
    assert application.enrichment.visit_allowed("url", "https://sbr-loans.com/login")


@pytest.mark.db
async def test_enrichment_no_visit_reads_current_takedown(clean_db: str) -> None:
    from opti.takedown.config import TakedownConfig

    application = await build_app(Settings(database_url=clean_db), enrichers={}, sinks=[])
    try:
        assert application.enrichment.visit_allowed("url", "https://t.me/x") is False
        override(application.config, takedown=TakedownConfig())
        assert application.enrichment.visit_allowed("url", "https://t.me/x") is True
        override(
            application.config,
            takedown=TakedownConfig.model_validate(
                {"platforms": [{"id": "telegram", "name": "Telegram", "hosts": ["t.me"]}]}
            ),
        )
        assert application.enrichment.visit_allowed("url", "https://t.me/x") is False
    finally:
        await application.close()


async def test_recompute_campaigns_task(app: tuple[App, FakeSink, dict[str, Any]]) -> None:
    application, _, _ = app
    now = datetime.now(UTC)
    async with application.sessions() as s, s.begin():
        await repo.upsert_project(s, application.rules)
        for value in ("sbr-task1.top", "sbr-task2.top"):
            entity = await repo.upsert_entity(s, "domain", value, now)
            entity.enrichment = {"dns": {"data": {"a": ["93.184.216.34"]}}}
            up = await repo.upsert_finding(
                s, project_id=application.rules.project, entity=entity,
                score=Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 70}),
                match={"domain": value}, source="certstream", now=now,
            )  # fmt: skip
            await repo.open_alert(s, up.finding, Severity.HIGH, now)
    result = (await (await recompute_campaigns.kiq()).wait_result()).return_value
    assert result == {"candidates": 1, "created": 1, "removed": 0, "pending": 0}
    async with application.sessions() as s:
        assert (await s.scalars(select(Campaign))).one().state == "candidate"


@pytest.mark.db
async def test_app_uses_saved_rules_after_refresh(clean_db: str, sbr_rules) -> None:  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    from opti.configs import kinds, revisions
    from opti.pipeline.app import build_app
    from opti.settings import Settings

    application = await build_app(Settings(database_url=clean_db), enrichers={}, sinks=[])
    try:
        before = application.processor
        data = kinds.to_data("rules", sbr_rules)
        data["project"] = "renamed"
        async with application.sessions.begin() as s:
            await revisions.append(s, "rules", kinds.from_data("rules", data), base_version=0,
                                   user="t", note=None, now=datetime.now(UTC))  # fmt: skip
        assert await application.config.refresh() is True
        assert application.rules.project == "renamed"
        assert application.processor is not before
        assert application.processor.rules.project == "renamed"
    finally:
        await application.close()
