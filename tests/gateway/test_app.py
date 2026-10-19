import hashlib
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.configs.connectors import ConnectorOverrides
from opti.configs.testing import override
from opti.core.config import ProjectRules
from opti.db.engine import make_sessionmaker
from opti.db.models import CollectorNode, ConnectorCursor, ConnectorRun
from opti.gateway.app import MAX_BODY_BYTES, MAX_ITEMS_PER_BATCH, create_gateway
from opti.gateway.jobs import Job, MemoryJobQueue
from opti.gateway.testing import OTHER_TOKEN, client_for, make_deps
from opti.storage.artifacts import MAX_ARTIFACT_BYTES
from opti.storage.objects import MemoryObjectStore

PROJECT = "sample-brand-protection"


def _item(
    connector: str = "dnstwist", project: str = PROJECT, sid: str = "sbr-loans.com"
) -> dict[str, object]:
    return {
        "connector_id": connector, "source_item_id": sid,
        "fetched_at": "2026-10-02T08:00:00+00:00", "url": None,
        "payload": {"matches": [{"domain": sid}]}, "project_ids": [project],
    }  # fmt: skip


async def test_requires_node_token(sbr_rules: ProjectRules) -> None:
    deps, _ = make_deps(sbr_rules)
    app = create_gateway(deps)
    async with client_for(app, token=None) as c:
        assert (await c.get("/v1/rules")).status_code == 401
    async with client_for(app, token="x" * 40) as c:
        assert (await c.get("/v1/rules")).status_code == 401
    async with client_for(app) as c:
        assert (await c.get("/v1/rules")).status_code == 200


async def test_new_project_items_refresh_gateway_before_rejecting(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opti.configs.runtime import ConfigSnapshot

    deps, enqueued = make_deps(sbr_rules)
    new = sbr_rules.model_copy(update={"project": "switched-project"})

    async def refresh() -> bool:
        deps.config.apply(ConfigSnapshot.of(new))
        return True

    monkeypatch.setattr(deps.config, "refresh", refresh)
    async with client_for(create_gateway(deps)) as c:
        r = await c.post("/v1/items", json={"items": [_item(project=new.project)]})
        assert r.status_code == 200, r.text
        assert enqueued[0].project_ids == (new.project,)
        assert (
            await c.post("/v1/items", json={"items": [_item(project="unrelated-project")]})
        ).status_code == 403


async def test_no_api_docs_exposed(sbr_rules: ProjectRules) -> None:
    deps, _ = make_deps(sbr_rules)
    async with client_for(create_gateway(deps)) as c:
        for path in ("/docs", "/openapi.json", "/redoc"):
            assert (await c.get(path)).status_code == 404


async def test_rules_endpoint(sbr_rules: ProjectRules) -> None:
    deps, _ = make_deps(sbr_rules)
    async with client_for(create_gateway(deps)) as c:
        body = (await c.get("/v1/rules")).json()
    assert body["rules"]["project"] == PROJECT and len(body["digest"]) == 64
    assert ProjectRules.model_validate(body["rules"]).domains == sbr_rules.domains


async def test_connector_config_requires_node_token_and_sends_managed_secret(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPTI_SECRET_URLSCAN_API_KEY", "platform-env-key")
    deps, _ = make_deps(sbr_rules)
    approved = {"enabled": True, "license_approved": True, "license_ref": "LEGAL-1"}
    override(
        deps.config,
        connectors=ConnectorOverrides.model_validate(
            {
                "connectors": {
                    "otx": approved,
                    "urlscan": approved,
                    "hibp": approved,
                    "virustotal": {**approved, "enabled": False},
                    "github_code": {**approved, "license_approved": False},
                }
            }
        ),
        secrets={
            "connectors": {
                "otx:api_key": "node-only-key",
                "hibp:api_key": "domestic-key",
                "virustotal:api_key": "disabled-key",
                "github_code:token": "unapproved-key",
            }
        },
    )
    app = create_gateway(deps)
    async with client_for(app, token=None) as c:
        assert (await c.get("/v1/connector-config")).status_code == 401
    async with client_for(app) as c:
        r = await c.get("/v1/connector-config")
    assert r.status_code == 200
    assert r.json()["instances"]["otx"]["license_approved"] is True
    assert r.json()["secrets"]["otx"]["api_key"] == "node-only-key"
    # 平台环境变量里的凭据不下发给采集节点
    assert r.json()["secrets"]["urlscan"] == {}
    assert "platform-env-key" not in r.text
    assert "hibp" not in r.json()["instances"]
    assert "virustotal" not in r.json()["secrets"] and "github_code" not in r.json()["secrets"]
    assert all(value not in r.text for value in ("domestic-key", "disabled-key", "unapproved-key"))


async def test_items_are_enqueued_with_node(sbr_rules: ProjectRules) -> None:
    deps, enqueued = make_deps(sbr_rules)
    async with client_for(create_gateway(deps)) as c:
        r = await c.post("/v1/items", json={"items": [_item(), _item(sid="sbr-grant.top")]})
    assert r.status_code == 200 and r.json() == {"accepted": 2}
    assert [i.source_item_id for i in enqueued] == ["sbr-loans.com", "sbr-grant.top"]
    assert enqueued[0].payload["collector_node"] == "hk1"
    assert enqueued[0].project_ids == (PROJECT,)


async def test_items_from_unknown_connector_or_project_rejected(sbr_rules: ProjectRules) -> None:
    deps, enqueued = make_deps(sbr_rules)
    async with client_for(create_gateway(deps)) as c:
        assert (
            await c.post("/v1/items", json={"items": [_item(), _item(connector="nope")]})
        ).status_code == 403
        assert (
            await c.post("/v1/items", json={"items": [_item(project="other")]})
        ).status_code == 403
        assert (
            await c.post("/v1/items", json={"items": [{"connector_id": "dnstwist"}]})
        ).status_code == 422
        too_many = [_item(sid=f"d{i}.com") for i in range(MAX_ITEMS_PER_BATCH + 1)]
        assert (await c.post("/v1/items", json={"items": too_many})).status_code == 422
    assert enqueued == []  # 整批拒绝，不会只入队一部分


async def test_lease_and_result_round_trip(sbr_rules: ProjectRules) -> None:
    jobs = MemoryJobQueue()
    deps, _ = make_deps(sbr_rules, jobs=jobs)
    job = Job.new(
        "enrich", {"enricher": "dns", "type": "domain", "value": "x.com"}, ttl=30, reply=True
    )
    await jobs.submit(job)
    async with client_for(create_gateway(deps)) as c:
        r = await c.post("/v1/jobs/lease", json={"wait": 1})
        assert r.status_code == 200 and Job.from_dict(r.json()) == job
        assert (await c.post("/v1/jobs/lease", json={"wait": 0.1})).status_code == 204
        assert (await c.post(f"/v1/jobs/{job.id}/result", json={"exists": True})).status_code == 204
    assert await jobs.wait(job.id, timeout=1) == {"exists": True}


async def test_lease_wait_is_capped(sbr_rules: ProjectRules) -> None:
    deps, _ = make_deps(sbr_rules)
    async with client_for(create_gateway(deps)) as c:
        assert (await c.post("/v1/jobs/lease", json={"wait": 3600})).status_code == 422


async def test_result_from_other_node_rejected(sbr_rules: ProjectRules) -> None:
    jobs = MemoryJobQueue()
    deps, _ = make_deps(sbr_rules, jobs=jobs)
    app = create_gateway(deps)
    job = Job.new("enrich", {"value": "x.com"}, ttl=30, reply=True)
    await jobs.submit(job)
    async with client_for(app) as hk1, client_for(app, token=OTHER_TOKEN) as sg1:
        assert (await hk1.post("/v1/jobs/lease", json={"wait": 1})).status_code == 200
        assert (
            await sg1.post(f"/v1/jobs/{job.id}/result", json={"forged": True})
        ).status_code == 409
        assert (await hk1.post(f"/v1/jobs/{job.id}/result", json={"ok": True})).status_code == 204


async def test_evidence_stored_with_verified_hash(sbr_rules: ProjectRules) -> None:
    store = MemoryObjectStore()
    deps, _ = make_deps(sbr_rules, store=store)
    data = b"\x89PNG screenshot"
    sha = hashlib.sha256(data).hexdigest()
    async with client_for(create_gateway(deps)) as c:
        r = await c.put(
            "/v1/evidence", params={"sha256": sha, "content_type": "image/png"}, content=data
        )
    assert r.status_code == 200
    ref = r.json()
    assert ref["sha256"] == sha and ref["node_id"] == "hk1" and ref["size"] == len(data)
    assert store.objects[ref["key"]] == data


async def test_evidence_hash_mismatch_rejected(sbr_rules: ProjectRules) -> None:
    store = MemoryObjectStore()
    deps, _ = make_deps(sbr_rules, store=store)
    async with client_for(create_gateway(deps)) as c:
        r = await c.put(
            "/v1/evidence", params={"sha256": "0" * 64, "content_type": "image/png"}, content=b"png"
        )
    assert r.status_code == 400 and store.objects == {}


async def test_evidence_limits(sbr_rules: ProjectRules) -> None:
    store = MemoryObjectStore()
    deps, _ = make_deps(sbr_rules, store=store)
    big = b"x" * (MAX_ARTIFACT_BYTES + 1)
    async with client_for(create_gateway(deps)) as c:
        r = await c.put(
            "/v1/evidence",
            params={"sha256": hashlib.sha256(big).hexdigest(), "content_type": "image/png"},
            content=big,
        )
        assert r.status_code == 413
        exe = b"MZ"
        r = await c.put(
            "/v1/evidence",
            params={
                "sha256": hashlib.sha256(exe).hexdigest(),
                "content_type": "application/x-msdownload",
            },
            content=exe,
        )
        assert r.status_code == 415
    assert store.objects == {}


@pytest.mark.db
async def test_run_job_lease_and_result_update_run_and_cursors(
    sbr_rules: ProjectRules, clean_db: str
) -> None:
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    now = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
    async with sessions() as s, s.begin():
        run = ConnectorRun(
            connector_id="crtsh", started_at=now, status="dispatched", items=0, errors=0, message=""
        )
        s.add(run)
        await s.flush()
        run_id = run.id
    jobs = MemoryJobQueue()
    deps, _ = make_deps(sbr_rules, jobs=jobs, sessions=sessions, clock=lambda: now)
    job = Job.new(
        "run_connector", {"run_id": run_id, "connector_id": "crtsh", "cursors": {}}, ttl=600
    )
    await jobs.submit(job)
    async with client_for(create_gateway(deps)) as c:
        assert (await c.post("/v1/jobs/lease", json={"wait": 1})).status_code == 200
        async with sessions() as s:
            leased = await s.get(ConnectorRun, run_id)
            assert leased is not None and leased.status == "running" and leased.node_id == "hk1"
        result = {"status": "ok", "items": 3, "message": "", "cursors": {"q:sbr": "99"}}
        assert (await c.post(f"/v1/jobs/{job.id}/result", json=result)).status_code == 204
    async with sessions() as s:
        done = await s.get(ConnectorRun, run_id)
        assert done is not None and done.status == "ok" and done.items == 3 and done.ended_at == now
        cursor = await s.scalar(
            select(ConnectorCursor.value).where(ConnectorCursor.connector_id == "crtsh")
        )
        assert cursor == "99"
    await engine.dispose()


@pytest.mark.db
async def test_heartbeat_upserts_node(sbr_rules: ProjectRules, clean_db: str) -> None:
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    now = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
    deps, _ = make_deps(sbr_rules, sessions=sessions, clock=lambda: now)
    async with client_for(create_gateway(deps)) as c:
        hb = {"version": "0.1.0", "status": {"streams": {"certstream": "running"}}}
        assert (await c.post("/v1/heartbeat", json=hb)).status_code == 204
        assert (await c.post("/v1/heartbeat", json=hb)).status_code == 204
    async with sessions() as s:
        node = await s.get(CollectorNode, "hk1")
        assert node is not None and node.last_seen == now
        assert node.status["streams"]["certstream"] == "running"
    await engine.dispose()


async def test_forged_content_length_does_not_bypass_batch_limit(sbr_rules: ProjectRules) -> None:
    deps, enqueued = make_deps(sbr_rules)
    async with client_for(create_gateway(deps)) as c:
        r = await c.post(
            "/v1/items",
            content=b"x" * (MAX_BODY_BYTES + 1),
            headers={"Content-Length": "1", "Content-Type": "application/json"},
        )
    assert r.status_code == 413 and not enqueued


async def test_push_sources_respect_gate_and_domestic_boundary(
    sbr_rules: ProjectRules, tmp_path
) -> None:
    deps, enqueued = make_deps(sbr_rules)
    deps.config_dir = tmp_path
    for source in ("canary", "public_report"):
        (tmp_path / f"{source}.yaml").write_text("enabled: true\nlicense_approved: true\n")
    async with client_for(create_gateway(deps)) as client:
        assert (
            await client.post(
                "/v1/items", json={"items": [_item("canary"), _item("public_report")]}
            )
        ).status_code == 200
        (tmp_path / "public_report.yaml").write_text("enabled: false\nlicense_approved: true\n")
        assert (
            await client.post("/v1/items", json={"items": [_item("public_report")]})
        ).status_code == 403
        for source in ("report_mailbox", "dmarc", "referer_log"):
            assert (
                await client.post("/v1/items", json={"items": [_item(source)]})
            ).status_code == 403
    assert len(enqueued) == 2
