from collections.abc import Awaitable, Callable

import httpx
import pytest
from sqlalchemy import select, update

from opti.configs import kinds
from opti.db.models import AuditLog, ConfigRevision
from tests.api.conftest import ApiWorld, SeededAlert

pytestmark = pytest.mark.db


async def _client(make_user, login, username: str, *roles: str) -> httpx.AsyncClient:
    await make_user(username, roles)
    return await login(username)


def _rules_yaml(api: ApiWorld, **changes: object) -> str:
    data = kinds.to_data("rules", api.rules)
    data.update(changes)
    return kinds.from_data("rules", data)


async def test_get_current_from_file(api: ApiWorld, make_user, login) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.get("/api/v1/config/rules")
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == 0 and body["source"] == "file"
    assert body["data"]["project"] == api.rules.project


async def test_save_creates_version_audits_and_refreshes(api: ApiWorld, make_user, login) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    text = _rules_yaml(api, authorization_ref="AUTH-2")
    r = await c.put("/api/v1/config/rules", json={"yaml": text, "base_version": 0, "note": "授权"})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 1 and r.json()["yaml"] == text
    assert api.deps.rules.authorization_ref == "AUTH-2"
    same = await c.put("/api/v1/config/rules", json={"yaml": text, "base_version": 1})
    assert same.json()["version"] == 1  # 内容未变不生成新版本
    async with api.sessions() as s:
        rows = list(
            await s.execute(
                select(AuditLog.action, AuditLog.detail).where(AuditLog.target_type == "config")
            )
        )
    assert [(a, d["version"]) for a, d in rows] == [("config.saved", 1)]
    assert "content" not in rows[0][1] and "yaml" not in rows[0][1]


async def test_save_rejects_stale_base_version(api: ApiWorld, make_user, login) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    await c.put(
        "/api/v1/config/rules",
        json={"yaml": _rules_yaml(api, authorization_ref="A"), "base_version": 0},
    )
    r = await c.put(
        "/api/v1/config/rules",
        json={"yaml": _rules_yaml(api, authorization_ref="B"), "base_version": 0},
    )
    assert r.status_code == 409
    assert r.json()["detail"] == {
        "reason": "version_conflict",
        "current_version": 1,
        "updated_by": "alice",
    }


async def test_project_change_needs_confirmation(
    api: ApiWorld, make_user, login, seed_alert: Callable[..., Awaitable[SeededAlert]]
) -> None:
    await seed_alert()
    c = await _client(make_user, login, "alice", "analyst", "platform_admin")
    body = {"yaml": _rules_yaml(api, project="other"), "base_version": 0}
    r = await c.put("/api/v1/config/rules", json=body)
    assert r.status_code == 409
    assert r.json()["detail"] == {
        "reason": "project_change",
        "from": api.rules.project,
        "to": "other",
        "alert_count": 1,
    }
    r = await c.put("/api/v1/config/rules", json={**body, "confirm_project_change": True})
    assert r.status_code == 200 and api.deps.rules.project == "other"


async def test_validation_errors(api: ApiWorld, make_user, login) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.post("/api/v1/config/rules/validate", json={"yaml": "project: [\n"})
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["errors"][0]["line"]
    data = kinds.to_data("rules", api.rules)
    r = await c.post("/api/v1/config/rules/validate", json={"data": data})
    assert r.json()["ok"] is True and r.json()["data"]["project"] == api.rules.project
    bad = await c.put("/api/v1/config/rules", json={"yaml": "x: &a 1\n", "base_version": 0})
    assert bad.status_code == 422 and bad.json()["detail"]["errors"]


async def test_history_diff_and_restore(api: ApiWorld, make_user, login) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    await c.put(
        "/api/v1/config/rules",
        json={"yaml": _rules_yaml(api, authorization_ref="A"), "base_version": 0},
    )
    await c.put(
        "/api/v1/config/rules",
        json={"yaml": _rules_yaml(api, authorization_ref="B"), "base_version": 1},
    )
    revs = (await c.get("/api/v1/config/rules/revisions")).json()
    assert [r["version"] for r in revs] == [2, 1]
    detail = (await c.get("/api/v1/config/rules/revisions/1")).json()
    assert "-authorization_ref: B" in detail["diff"] and "+authorization_ref: A" in detail["diff"]
    r = await c.post("/api/v1/config/rules/revisions/1/restore", json={"base_version": 2})
    assert r.status_code == 200 and r.json()["version"] == 3 and r.json()["restored_from"] == 1
    assert api.deps.rules.authorization_ref == "A"


async def test_permissions(api: ApiWorld, make_user, login) -> None:
    viewer = await _client(make_user, login, "vic", "viewer")
    assert (await viewer.get("/api/v1/config/organization")).status_code == 200
    assert (await viewer.get("/api/v1/config/rules")).status_code == 403
    assert (await viewer.get("/api/v1/config/status")).status_code == 200
    analyst = await _client(make_user, login, "alice", "analyst")
    org = {"data": {"name": "Acme"}, "base_version": 0}
    assert (await analyst.put("/api/v1/config/organization", json=org)).status_code == 403
    admin = await _client(make_user, login, "ops", "platform_admin")
    assert (await admin.put("/api/v1/config/organization", json=org)).status_code == 200
    assert api.deps.organization.name == "Acme"
    rules = {"yaml": _rules_yaml(api), "base_version": 0}
    assert (await admin.put("/api/v1/config/rules", json=rules)).status_code == 403


async def test_status_lists_processes(api: ApiWorld, make_user, login) -> None:
    from opti.configs import revisions

    async with api.sessions.begin() as s:
        await revisions.report_status(
            s,
            process="worker@h",
            kind="rules",
            version=0,
            digest="d",
            error=None,
            now=api.clock(),
        )
    c = await _client(make_user, login, "alice", "analyst")
    body = (await c.get("/api/v1/config/status")).json()
    assert body["current"] == {kind: 0 for kind in kinds.KINDS}
    assert [(p["process"], p["kind"], p["stale"], p["edge"]) for p in body["processes"]] == [
        ("worker@h", "rules", False, False)
    ]


async def _corrupt_rules_head(api: ApiWorld, version: int) -> None:
    async with api.sessions.begin() as s:
        await s.execute(
            update(ConfigRevision)
            .where(ConfigRevision.kind == "rules", ConfigRevision.version == version)
            .values(content="project: [\n")
        )


async def test_unreadable_head_get_and_put_keep_version(api: ApiWorld, make_user, login) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    saved = await c.put("/api/v1/config/rules", json={"yaml": _rules_yaml(api), "base_version": 0})
    assert saved.status_code == 200, saved.text
    version = saved.json()["version"]
    await _corrupt_rules_head(api, version)
    got = await c.get("/api/v1/config/rules")
    assert got.status_code == 200, got.text
    body = got.json()
    live = api.deps.config.snapshot.rules
    assert body["version"] == version and body["source"] == "db"
    assert body["data"]["project"] == live.project
    assert body["yaml"] == kinds.from_data("rules", kinds.to_data("rules", live))
    text = _rules_yaml(api, authorization_ref="AFTER-CORRUPT")
    put = await c.put("/api/v1/config/rules", json={"yaml": text, "base_version": version})
    assert put.status_code == 200, put.text
    assert put.json()["version"] == version + 1
    assert api.deps.rules.authorization_ref == "AFTER-CORRUPT"


async def test_unreadable_head_project_change_uses_live_project(
    api: ApiWorld, make_user, login
) -> None:
    c = await _client(make_user, login, "alice", "analyst", "platform_admin")
    saved = await c.put("/api/v1/config/rules", json={"yaml": _rules_yaml(api), "base_version": 0})
    assert saved.status_code == 200, saved.text
    version = saved.json()["version"]
    await _corrupt_rules_head(api, version)
    r = await c.put(
        "/api/v1/config/rules",
        json={"yaml": _rules_yaml(api, project="other"), "base_version": version},
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == {
        "reason": "project_change",
        "from": api.deps.config.snapshot.rules.project,
        "to": "other",
        "alert_count": 0,
    }


async def test_get_file_backed_alerting(api: ApiWorld, make_user, login) -> None:
    viewer = await _client(make_user, login, "vic", "viewer")
    r = await viewer.get("/api/v1/config/alerting")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "alerting" and body["version"] == 0 and body["source"] == "file"
    assert isinstance(body["data"].get("channels"), list)


async def test_alerting_write_requires_platform_admin(api: ApiWorld, make_user, login) -> None:
    analyst = await _client(make_user, login, "alice", "analyst")
    denied = await analyst.put("/api/v1/config/alerting", json={"data": {}, "base_version": 0})
    assert denied.status_code == 403
    admin = await _client(make_user, login, "ops", "platform_admin")
    saved = await admin.put("/api/v1/config/alerting", json={"data": {}, "base_version": 0})
    assert saved.status_code == 200, saved.text
    assert saved.json()["version"] == 1 and saved.json()["source"] == "db"


async def test_alerting_current_digest_matches_applied_process(
    api: ApiWorld, make_user, login
) -> None:
    from datetime import UTC, datetime

    from opti.configs import revisions, secrets
    from opti.configs.runtime import ConfigRuntime
    from opti.core.secretbox import Keyring, generate_key

    keyring = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    assert keyring is not None
    rt = await ConfigRuntime.start(
        api.deps.settings, api.sessions, process="worker@t", keyring=keyring
    )
    c = await _client(make_user, login, "alice", "analyst")
    now = datetime(2026, 10, 12, tzinfo=UTC)

    async def digests() -> tuple[dict[str, str], str]:
        body = (await c.get("/api/v1/config/status")).json()
        reported = next(
            p["digest"]
            for p in body["processes"]
            if p["process"] == "worker@t" and p["kind"] == "alerting"
        )
        return body["current_digest"], reported

    current, reported = await digests()
    file_digest = kinds.digest_of(kinds.read_file("alerting", api.deps.settings))
    assert current["rules"] == kinds.digest_of(kinds.read_file("rules", api.deps.settings))
    assert reported == current["alerting"] != file_digest

    async with api.sessions.begin() as s:
        await secrets.write(
            s,
            "alerting",
            {"channel:teams:webhook_url": "https://db.example/hook-0001"},
            keyring=keyring,
            user="ops",
            now=now,
        )
    assert await rt.refresh() is True
    current, reported = await digests()
    assert reported == current["alerting"] != file_digest

    data = kinds.to_data("alerting", rt.snapshot.alerting)
    data["channels"] = [
        {"id": "secops", "name": "值班", "type": "teams", "severities": ["critical"]}
    ]
    async with api.sessions.begin() as s:
        await revisions.append(
            s, "alerting", kinds.from_data("alerting", data), base_version=0,
            user="ops", note=None, now=now,
        )  # fmt: skip
    assert await rt.refresh() is True
    current, reported = await digests()
    assert rt.snapshot.alerting_version == 1
    assert reported == current["alerting"] != file_digest


async def test_status_includes_edge_services(api: ApiWorld, make_user, login) -> None:
    import json

    from opti.configs.runtime import EDGE_STATUS_KEY
    from opti.configs.testing import FakeKV

    kv = FakeKV()
    api.deps.edge_store = kv
    kv.hashes[EDGE_STATUS_KEY] = {"intake@e": json.dumps({
        "kind": "rules", "version": 2, "digest": "d", "error": None,
        "updated_at": api.clock().isoformat(),
    })}  # fmt: skip
    c = await _client(make_user, login, "alice", "analyst")
    body = (await c.get("/api/v1/config/status")).json()
    assert [(p["process"], p["edge"]) for p in body["processes"]] == [("intake@e", True)]
