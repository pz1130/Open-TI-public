import hashlib
from typing import Any

import pytest
from sqlalchemy import select

from opti.db import repo
from opti.db.models import AuditLog, DomainObservation, Evidence
from opti.pipeline import watchlist

pytestmark = pytest.mark.db


async def seed_page(api: Any, *, project: str | None = None) -> tuple[int, int]:
    rules = api.rules if project is None else api.rules.model_copy(update={"project": project})
    now = api.clock()
    stored = await api.store.put("evidence/watch-page.png", b"saved screenshot", "image/png")
    async with api.sessions.begin() as session:
        await repo.upsert_project(session, rules)
        await watchlist.ensure_watched(
            session, rules.project, "sbr.example", reason="test", now=now
        )
        row = next(
            row for row in await watchlist.due(session, now) if row.project_id == rules.project
        )
        observation = DomainObservation(
            watched_domain_id=row.id,
            observed_at=now,
            state="parked",
            fingerprint={},
            changes=[],
            data={
                "capture_status": "done",
                "page": {
                    "reachable": True,
                    "status": 200,
                    "title": "Buy this domain",
                    "text_excerpt": "SBR.example is available for purchase.",
                    "final_url": "https://sedo.com/search",
                    "source": "browser",
                    "verdict": "parking",
                    "redirects": ["https://sbr.example/"],
                },
            },
        )
        session.add(observation)
        await session.flush()
        ev = Evidence(
            finding_id=None,
            watch_observation_id=observation.id,
            kind="screenshot",
            object_key=stored.key,
            sha256=stored.sha256,
            size=stored.size,
            content_type="image/png",
            captured_at=now,
            method="sandbox-test",
            node_id="test-node",
            source_url="https://sedo.com/search",
        )
        session.add(ev)
        await session.flush()
        return row.id, ev.id


async def test_watchlist_exposes_content_and_authenticated_evidence(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    client = await login()
    watch_id, evidence_id = await seed_page(api)
    page = (await client.get("/api/v1/watchlist")).json()["items"][0]["inspection"]
    assert (
        page["title"] == "Buy this domain"
        and page["source"] == "browser"
        and page["verdict"] == "parking"
    )
    assert page["evidence"][0]["id"] == evidence_id
    history = (await client.get(f"/api/v1/watchlist/{watch_id}/observations")).json()
    assert history[0]["inspection"]["text_excerpt"] == page["text_excerpt"]
    downloaded = await client.get(f"/api/v1/evidence/{evidence_id}/content")
    assert downloaded.status_code == 200 and downloaded.content == b"saved screenshot"
    assert downloaded.headers["x-content-sha256"] == hashlib.sha256(downloaded.content).hexdigest()
    assert downloaded.headers["content-type"] == "image/png"
    async with api.sessions() as session:
        assert (
            await session.scalar(select(AuditLog.id).where(AuditLog.action == "evidence.download"))
            is not None
        )


async def test_watchlist_viewer_gets_content_but_not_screenshots(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("vic", ("viewer",))
    client = await login("vic")
    watch_id, evidence_id = await seed_page(api)
    page = (await client.get("/api/v1/watchlist")).json()["items"][0]["inspection"]
    assert page["evidence"] == [] and page["title"] == "Buy this domain"
    assert (await client.get(f"/api/v1/watchlist/{watch_id}/observations")).json()[0]["inspection"][
        "evidence"
    ] == []
    assert (await client.get(f"/api/v1/evidence/{evidence_id}/content")).status_code == 403


async def test_foreign_project_screenshot_and_corrupted_blob_are_rejected(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    client = await login()
    _, foreign = await seed_page(api, project="other-project")
    assert (await client.get(f"/api/v1/evidence/{foreign}/content")).status_code == 404
    _, own = await seed_page(api)
    await api.store.put("evidence/watch-page.png", b"tampered", "image/png")
    assert (await client.get(f"/api/v1/evidence/{own}/content")).status_code == 409
