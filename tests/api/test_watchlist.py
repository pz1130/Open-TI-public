from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from opti.configs.runtime import ConfigSnapshot
from opti.db import repo
from opti.db.models import AuditLog, DomainObservation, WatchedDomain
from opti.pipeline.tasks import recheck_watched_domain

pytestmark = pytest.mark.db
UserFactory = Callable[..., Awaitable[int]]


async def test_add_list_remove(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user()
    c = await login()
    r = await c.post("/api/v1/watchlist", json={"domain": " SBR-Loans.COM. ", "reason": "举报邮件"})
    assert r.status_code == 201
    w = r.json()
    assert w["domain"] == "sbr-loans.com" and w["state"] == "unknown" and "举报邮件" in w["reason"]
    assert (
        await c.post("/api/v1/watchlist", json={"domain": "sbr-loans.com", "reason": "x"})
    ).status_code == 409
    assert (
        await c.post("/api/v1/watchlist", json={"domain": "not a domain", "reason": "x"})
    ).status_code == 422
    page = (await c.get("/api/v1/watchlist")).json()
    assert [i["domain"] for i in page["items"]] == ["sbr-loans.com"]
    assert (
        await c.delete(f"/api/v1/watchlist/{w['id']}", params={"reason": "已注销"})
    ).status_code == 204
    assert (await c.delete(f"/api/v1/watchlist/{w['id']}")).status_code == 409
    assert (await c.get("/api/v1/watchlist")).json()["items"] == []
    assert (
        len((await c.get("/api/v1/watchlist", params={"include_expired": True})).json()["items"])
        == 1
    )
    again = await c.post("/api/v1/watchlist", json={"domain": "sbr-loans.com", "reason": "复活"})
    assert (
        again.status_code == 201
        and again.json()["id"] == w["id"]
        and again.json()["expires_at"] is None
    )
    async with api.sessions() as s:
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
    assert actions.count("watchlist.add") == 2 and actions.count("watchlist.remove") == 1


async def test_add_uses_one_project_snapshot_during_config_refresh(
    api: Any, make_user: UserFactory, login: Any, monkeypatch: Any
) -> None:
    await make_user()
    client = await login()
    old_project = api.rules.project
    changed = api.rules.model_copy(update={"project": "next-project"})
    original = repo.upsert_project

    async def switch_after_upsert(session: Any, rules: Any) -> None:
        await original(session, rules)
        api.deps.config.apply(ConfigSnapshot.of(changed, api.deps.organization))

    monkeypatch.setattr(repo, "upsert_project", switch_after_upsert)
    response = await client.post(
        "/api/v1/watchlist", json={"domain": "snapshot.example", "reason": "test"}
    )
    assert response.status_code == 201, response.text
    async with api.sessions() as session:
        watched = await session.scalar(
            select(WatchedDomain).where(WatchedDomain.id == response.json()["id"])
        )
    assert watched is not None and watched.project_id == old_project
    assert api.deps.rules.project == "next-project"


async def test_observations_timeline(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user()
    c = await login()
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, api.rules)
    w = (await c.post("/api/v1/watchlist", json={"domain": "sbr-loans.com", "reason": "t"})).json()
    async with api.sessions.begin() as s:
        s.add(DomainObservation(
            watched_domain_id=w["id"], observed_at=api.clock(), state="parked",
            fingerprint={"title": "for sale"}, changes=["state:unknown->parked"], data={},
        ))  # fmt: skip
    obs = (await c.get(f"/api/v1/watchlist/{w['id']}/observations")).json()
    assert obs[0]["state"] == "parked" and obs[0]["changes"] == ["state:unknown->parked"]


async def test_edit_watch_preserves_history_and_rejects_duplicate(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    c = await login()
    old = (
        await c.post("/api/v1/watchlist", json={"domain": "old.example", "reason": "original"})
    ).json()
    async with api.sessions.begin() as s:
        s.add(DomainObservation(
            watched_domain_id=old["id"], observed_at=api.clock(), state="no_dns",
            fingerprint={}, changes=[], data={},
        ))  # fmt: skip

    reason = await c.put(
        f"/api/v1/watchlist/{old['id']}",
        json={"domain": "old.example", "reason": "corrected"},
    )
    assert reason.status_code == 200
    assert reason.json()["id"] == old["id"]
    assert reason.json()["reason"] == "manual:alice: corrected"

    renamed = await c.put(
        f"/api/v1/watchlist/{old['id']}",
        json={"domain": "new.example", "reason": "corrected"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["id"] != old["id"]
    assert renamed.json()["state"] == "unknown"
    assert renamed.json()["last_checked_at"] is None
    assert (await c.get("/api/v1/watchlist")).json()["items"][0]["domain"] == "new.example"
    assert (await c.get(f"/api/v1/watchlist/{old['id']}/observations")).json()[0][
        "state"
    ] == "no_dns"
    assert (await c.get(f"/api/v1/watchlist/{renamed.json()['id']}/observations")).json() == []
    assert (
        await c.put(
            f"/api/v1/watchlist/{renamed.json()['id']}",
            json={"domain": "new.example", "reason": "later"},
        )
    ).status_code == 200
    other = (
        await c.post("/api/v1/watchlist", json={"domain": "other.example", "reason": "other"})
    ).json()
    assert (
        await c.put(
            f"/api/v1/watchlist/{renamed.json()['id']}",
            json={"domain": other["domain"], "reason": "collision"},
        )
    ).status_code == 409
    assert (
        await c.put(
            f"/api/v1/watchlist/{old['id']}",
            json={"domain": "unused.example", "reason": "removed"},
        )
    ).status_code == 409
    async with api.sessions() as s:
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
    assert actions.count("watchlist.update") == 3


async def test_edit_reason_records_editor_without_doubling_prefix(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    await make_user("bob")
    alice = await login()
    added = (
        await alice.post("/api/v1/watchlist", json={"domain": "old.example", "reason": "note"})
    ).json()
    assert added["reason"] == "manual:alice: note"
    bob = await login("bob")
    # 编辑框会把带前缀的原因原样填进来
    edited = await bob.put(
        f"/api/v1/watchlist/{added['id']}",
        json={"domain": "old.example", "reason": "manual:alice: corrected"},
    )
    assert edited.json()["reason"] == "manual:bob: corrected"


async def test_edit_domain_keeps_unchanged_reason_and_expiry(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    c = await login()
    until = api.clock() + timedelta(days=90)
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, api.rules)
        row = WatchedDomain(
            project_id=api.rules.project, domain="revived.example", reason="takedown #12 removed",
            state="unknown", created_at=api.clock(), next_check_at=api.clock(),
            last_fingerprint={}, expires_at=until,
        )  # fmt: skip
        s.add(row)
        await s.flush()
        watch_id = row.id
    renamed = await c.put(
        f"/api/v1/watchlist/{watch_id}",
        json={"domain": "revived-new.example", "reason": "takedown #12 removed"},
    )
    assert renamed.status_code == 200, renamed.text
    body = renamed.json()
    assert body["reason"] == "takedown #12 removed"
    async with api.sessions() as s:
        new = await s.get(WatchedDomain, body["id"])
        assert new is not None and new.expires_at == until


async def test_viewer_is_read_only(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user("vic", roles=("viewer",))
    c = await login("vic")
    assert (await c.get("/api/v1/watchlist")).status_code == 200
    assert (
        await c.post("/api/v1/watchlist", json={"domain": "sbr-loans.com", "reason": "x"})
    ).status_code == 403
    assert (
        await c.put("/api/v1/watchlist/1", json={"domain": "sbr-loans.com", "reason": "x"})
    ).status_code == 403
    assert (await c.post("/api/v1/watchlist/1/check")).status_code == 403


async def test_check_watch_queues_only_active_project_domain(
    api: Any, make_user: UserFactory, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_user()
    c = await login()
    api.app.state.deps.settings = replace(api.app.state.deps.settings, broker_url="redis://unused")
    queued: list[tuple[int, str | None]] = []

    async def enqueue(watch_id: int, checked_at: str | None) -> None:
        queued.append((watch_id, checked_at))

    monkeypatch.setattr(recheck_watched_domain, "kiq", enqueue)
    item = (
        await c.post("/api/v1/watchlist", json={"domain": "example.com", "reason": "manual"})
    ).json()
    async with api.sessions.begin() as s:
        watched = await s.get(WatchedDomain, item["id"])
        assert watched is not None
        watched.expires_at = api.clock() + timedelta(days=1)
    assert (await c.get("/api/v1/watchlist")).json()["items"][0]["id"] == item["id"]
    receipt = await c.post(f"/api/v1/watchlist/{item['id']}/check")
    assert receipt.status_code == 202
    assert receipt.json() == {
        "status": "queued",
        "watch_id": item["id"],
        "request_id": receipt.headers["X-Request-ID"],
    }
    assert queued == [(item["id"], None)]
    assert (await c.post("/api/v1/watchlist/999999/check")).status_code == 404
    assert (await c.delete(f"/api/v1/watchlist/{item['id']}")).status_code == 204
    assert (await c.post(f"/api/v1/watchlist/{item['id']}/check")).status_code == 409
    assert queued == [(item["id"], None)]
    async with api.sessions() as s:
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
    assert actions.count("watchlist.check_requested") == 1


async def test_numbered_watch_pages_count_the_same_filters(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    client = await login()
    ids = []
    for domain in ("alpha-one.example", "alpha-two.example", "beta.example"):
        row = await client.post("/api/v1/watchlist", json={"domain": domain, "reason": "page test"})
        assert row.status_code == 201, row.text
        ids.append(row.json()["id"])
    url = "/api/v1/watchlist"
    page = (await client.get(url, params={"page": 2, "limit": 1, "q": "alpha"})).json()
    assert page["total"] == 2 and [r["id"] for r in page["items"]] == [ids[0]]
    await client.delete(f"{url}/{ids[1]}")
    page = (await client.get(url, params={"page": 2, "limit": 1, "q": "alpha"})).json()
    assert page["total"] == 1 and page["items"] == []
    page = (
        await client.get(url, params={"page": 2, "limit": 1, "q": "alpha", "include_expired": True})
    ).json()
    assert page["total"] == 2 and [r["id"] for r in page["items"]] == [ids[0]]
