import asyncio
from typing import Any

import pytest
from sqlalchemy import select

from opti.configs import kinds, projects, revisions
from opti.configs.runtime import ConfigRuntime
from opti.db.models import AuditLog, ConfigRevision, Project

pytestmark = pytest.mark.db


async def test_concurrent_switches_do_not_overwrite_each_other(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("admin", ("platform_admin",))
    admin = await login("admin")
    async with api.sessions.begin() as s:
        for pid in ("second", "third"):
            await projects.save(
                s, api.rules.model_copy(update={"project": pid, "authorization_ref": pid})
            )
    responses = await asyncio.gather(
        *[
            admin.post(
                "/api/v1/admin/projects/activate", json={"project_id": pid, "base_version": 0}
            )
            for pid in ("second", "third")
        ]
    )
    assert sorted(r.status_code for r in responses) == [200, 409]
    winner = next(r.json()["project_id"] for r in responses if r.status_code == 200)
    assert api.deps.rules.project == winner and api.deps.rules.authorization_ref == winner
    async with api.sessions() as s:
        assert (
            len(list(await s.scalars(select(ConfigRevision).where(ConfigRevision.kind == "rules"))))
            == 1
        )
        assert (
            kinds.parse("rules", (await s.get(Project, api.rules.project)).rules_yaml) == api.rules
        )


async def test_round_trip_restores_rules_and_data_for_every_user(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    await make_user("admin", ("platform_admin", "analyst"))
    await make_user("viewer", ("viewer",))
    admin, viewer = await login("admin"), await login("viewer")
    alert = await seed_alert()
    watched = await admin.post(
        "/api/v1/watchlist", json={"domain": "sbr-loans.com", "reason": "test"}
    )
    assert watched.status_code == 201
    cert = await admin.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    assert cert.status_code == 201

    # The original project starts from file (v0); it must be saved before switching away.
    data = kinds.to_data("rules", api.rules)
    data.update(project="second", authorization_ref="SECOND-1")
    data["domains"]["brand_tokens"] = ["secondbrand"]
    target = kinds.parse("rules", kinds.from_data("rules", data))
    response = await admin.put(
        "/api/v1/config/rules",
        json={
            "yaml": projects.rules_text(target),
            "base_version": 0,
            "confirm_project_change": True,
        },
    )
    assert response.status_code == 200, response.text
    assert (await viewer.get("/api/v1/projects/current")).json()["project_id"] == "second"
    for path in ("alerts", "watchlist", "certificate-monitors"):
        assert (await viewer.get(f"/api/v1/{path}")).json()["items"] == []

    # Ordinary edits of the active project's rules become its next saved snapshot.
    target = target.model_copy(update={"authorization_ref": "SECOND-EDITED"})
    assert (
        await admin.put(
            "/api/v1/config/rules",
            json={
                "yaml": projects.rules_text(target),
                "base_version": 1,
            },
        )
    ).status_code == 200
    response = await admin.post(
        "/api/v1/admin/projects/activate",
        json={
            "project_id": api.rules.project,
            "base_version": 2,
        },
    )
    assert response.status_code == 200, response.text
    assert api.deps.rules == api.rules
    assert [x["id"] for x in (await viewer.get("/api/v1/alerts")).json()["items"]] == [
        alert.alert_id
    ]
    assert [x["id"] for x in (await viewer.get("/api/v1/watchlist")).json()["items"]] == [
        watched.json()["id"]
    ]
    assert [
        x["id"] for x in (await viewer.get("/api/v1/certificate-monitors")).json()["items"]
    ] == [cert.json()["id"]]

    # A separate service runtime sees the same globally activated project on refresh.
    worker = ConfigRuntime.static(target, sessions=api.sessions)
    await worker.refresh()
    assert worker.snapshot.rules == api.rules
    response = await admin.post(
        "/api/v1/admin/projects/activate",
        json={
            "project_id": "second",
            "base_version": 3,
        },
    )
    assert response.status_code == 200, response.text
    assert api.deps.rules == target
    await worker.refresh()
    assert worker.snapshot.rules == target
    async with api.sessions() as s:
        changes = list(
            await s.scalars(
                select(AuditLog)
                .where(AuditLog.action == "config.project_changed")
                .order_by(AuditLog.id)
            )
        )
        assert [(x.detail["from"], x.detail["to"]) for x in changes] == [
            (api.rules.project, "second"),
            ("second", api.rules.project),
            (api.rules.project, "second"),
        ]
        assert kinds.parse("rules", (await s.get(Project, "second")).rules_yaml) == target


async def test_project_permissions_and_stale_browser_writes(
    api: Any, make_user: Any, login: Any
) -> None:
    for role in ("analyst", "viewer", "auditor", "responder", "compliance_officer"):
        await make_user(role, (role,))
        client = await login(role)
        assert (await client.get("/api/v1/projects/current")).status_code == 200
        assert (await client.get("/api/v1/admin/projects")).status_code == 403
        assert (
            await client.post(
                "/api/v1/admin/projects/activate",
                json={"project_id": api.rules.project, "base_version": 0},
            )
        ).status_code == 403
    analyst = await login("analyst")
    changed = api.rules.model_copy(update={"project": "forbidden"})
    assert (
        await analyst.put(
            "/api/v1/config/rules",
            json={
                "yaml": projects.rules_text(changed),
                "base_version": 0,
                "confirm_project_change": True,
            },
        )
    ).status_code == 403
    response = await analyst.post(
        "/api/v1/watchlist",
        json={"domain": "sbr-loans.com", "reason": "test"},
        headers={"X-Opti-Project": "previous-project"},
    )
    assert response.status_code == 409 and response.json()["detail"]["reason"] == "project_changed"
    assert (await analyst.get("/api/v1/watchlist")).json()["items"] == []


async def test_legacy_history_recovery_missing_rules_pagination_and_conflicts(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("admin", ("platform_admin",))
    client = await login("admin")
    legacy = api.rules.model_copy(update={"project": "legacy", "authorization_ref": "OLD"})
    newest = legacy.model_copy(update={"authorization_ref": "LATEST"})
    async with api.sessions.begin() as s:
        for version, rules in enumerate((legacy, newest, api.rules)):
            await revisions.append(
                s,
                "rules",
                projects.rules_text(rules),
                base_version=version,
                user="old-admin",
                note=None,
                now=api.clock(),
            )
        s.add(Project(id="missing", name="Missing", authorization_ref="test"))
        s.add(
            Project(
                id="corrupt", name="Corrupt", authorization_ref="test", rules_yaml="project: [\n"
            )
        )
    await api.deps.config.refresh()
    page = (await client.get("/api/v1/admin/projects", params={"page_size": 1, "page": 2})).json()
    assert page["total"] == 4 and len(page["items"]) == 1 and page["rules_version"] == 3
    items = {
        x["project_id"]: x for x in (await client.get("/api/v1/admin/projects")).json()["items"]
    }
    assert (
        items["legacy"]["available"]
        and not items["missing"]["available"]
        and not items["corrupt"]["available"]
    )
    for pid, version, status in (
        ("missing", 3, 409),
        ("corrupt", 3, 409),
        ("absent", 3, 404),
        ("legacy", 0, 409),
    ):
        r = await client.post(
            "/api/v1/admin/projects/activate", json={"project_id": pid, "base_version": version}
        )
        assert r.status_code == status, r.text
    assert api.deps.rules == api.rules
    response = await client.post(
        "/api/v1/admin/projects/activate", json={"project_id": "legacy", "base_version": 3}
    )
    assert response.status_code == 200, response.text
    assert api.deps.rules == newest
    async with api.sessions() as s:
        assert (
            await s.scalar(select(ConfigRevision.version).order_by(ConfigRevision.version.desc()))
            == 4
        )
