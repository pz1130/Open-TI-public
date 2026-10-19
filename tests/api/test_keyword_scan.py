import asyncio
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from opti.api.routes import keyword_scan
from opti.configs import projects
from opti.db.models import AuditLog, ConnectorRun
from opti.pipeline.tasks import scan_keywords

pytestmark = pytest.mark.db
URL = "/api/v1/rules/scan"


def prepare(api: Any, monkeypatch: Any, *, fail: bool = False) -> list[tuple[str, dict[str, Any]]]:
    api.deps.settings = replace(api.deps.settings, broker_url="redis://localhost:6379/0")
    queued = []

    async def catalog(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return [{"id": m.id, "runnable": True} for m in api.deps.registry.manifests()]

    async def enqueue(cid: str, spec: dict[str, Any]) -> None:
        if fail:
            raise ConnectionError("queue down")
        queued.append((cid, spec))

    monkeypatch.setattr(keyword_scan.connector_catalog, "catalog", catalog)
    monkeypatch.setattr(scan_keywords, "kiq", enqueue)
    return queued


async def test_scopes_enqueue_saved_selection_and_block_duplicate_submissions(
    api: Any, make_user: Any, login: Any, monkeypatch: Any
) -> None:
    await make_user()
    client = await login()
    queued = prepare(api, monkeypatch)
    body = {"scope": "domain", "term": "samplebrand", "base_version": 0}
    results = await asyncio.gather(client.post(URL, json=body), client.post(URL, json=body))
    assert all(r.status_code == 202 for r in results)
    assert len(queued) == 3 and {cid for cid, _ in queued} == {"crtsh", "dnstwist", "urlscan"}
    assert all(
        spec
        == {
            "project_id": api.rules.project,
            "rules_version": 0,
            "scope": "domain",
            "term": "samplebrand",
        }
        for _, spec in queued
    )
    assert {r.json()["connectors"]["crtsh"]["status"] for r in results} == {"queued", "running"}
    async with api.sessions() as s:
        assert (
            len(
                list(
                    await s.scalars(select(AuditLog).where(AuditLog.action == "rules.scan_queued"))
                )
            )
            == 3
        )


async def test_permissions_queue_config_privacy_and_version_checks(
    api: Any, make_user: Any, login: Any, monkeypatch: Any
) -> None:
    await make_user("viewer", ("viewer",))
    viewer = await login("viewer")
    body = {"scope": "text", "term": "Sample Brand", "base_version": 0}
    assert (await viewer.post(URL, json=body)).status_code == 403
    await make_user()
    client = await login()
    assert (await client.post(URL, json=body)).status_code == 503
    queued = prepare(api, monkeypatch)
    for term in ("SBR", "unsaved"):
        assert (await client.post(URL, json={**body, "term": term})).status_code == 422
    assert (await client.post(URL, json={**body, "base_version": 10})).status_code == 409
    assert queued == []
    r = await client.post(URL, json=body)
    assert r.status_code == 202, r.text
    assert {cid for cid, _ in queued} == {
        "google_news",
        "brave_news",
        "gdelt_doc",
        "urlscan",
        "otx",
        "reddit_search",
        "gitlab_projects",
        "app_store_search",
    }


async def test_busy_sources_min_interval_unavailable_and_queue_errors_are_visible(
    api: Any, make_user: Any, login: Any, monkeypatch: Any
) -> None:
    await make_user()
    client = await login()
    queued = prepare(api, monkeypatch)
    now = api.clock()
    async with api.sessions.begin() as s:
        s.add_all(
            [
                ConnectorRun(connector_id="crtsh", status="running", started_at=now),
                ConnectorRun(
                    connector_id="dnstwist", status="ok", started_at=now - timedelta(hours=1)
                ),
            ]
        )
    r = await client.post(URL, json={"scope": "domain", "term": "sbr", "base_version": 0})
    statuses = {cid: x["status"] for cid, x in r.json()["connectors"].items()}
    assert statuses == {"crtsh": "running", "dnstwist": "too_soon", "urlscan": "queued"}
    assert len(queued) == 1
    prepare(api, monkeypatch, fail=True)
    r = await client.post(
        URL, json={"scope": "text", "term": "Sample Brand", "base_version": 0}
    )
    assert r.json()["connectors"]["google_news"]["reason"] == "queue_error"


async def test_superseded_pending_scan_does_not_block_new_rules(
    api: Any, make_user: Any, login: Any, monkeypatch: Any
) -> None:
    await make_user()
    client = await login()
    queued = prepare(api, monkeypatch)
    body = {"scope": "domain", "term": "sbr", "base_version": 0}
    assert (await client.post(URL, json=body)).status_code == 202
    updated = api.rules.model_copy(update={"authorization_ref": "UPDATED"})
    assert (
        await client.put(
            "/api/v1/config/rules", json={"yaml": projects.rules_text(updated), "base_version": 0}
        )
    ).status_code == 200
    assert (await client.post(URL, json={**body, "base_version": 1})).status_code == 202
    assert len(queued) == 6
