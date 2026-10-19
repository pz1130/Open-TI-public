from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import AccountCandidate, AuditLog, ProtectedAccount
from opti.pipeline.tasks import check_protected_account

pytestmark = pytest.mark.db
URL = "/api/v1/protected-accounts"


async def test_crud_validation_and_audit(api: Any, make_user: Any, login: Any) -> None:
    await make_user()
    client = await login()
    added = await client.post(
        URL,
        json={
            "platform": "mastodon",
            "handle": " @SBRank@Mastodon.Social ",
            "label": "官方账号",
            "extra_queries": ["  样本  银行 ", "样本 银行"],
            "allowed_accounts": ["@sbr-fans@mastodon.social", "sbr-fans@mastodon.social"],
        },
    )
    assert added.status_code == 201, added.text
    row = added.json()
    assert row["handle"] == "sbrank@mastodon.social"
    assert row["extra_queries"] == ["样本 银行"]
    assert row["allowed_accounts"] == ["sbr-fans@mastodon.social"]
    assert row["candidate_count"] == 0 and row["adapter_ready"] is False
    duplicate = {"platform": "mastodon", "handle": "sbrank@mastodon.social"}
    assert (await client.post(URL, json=duplicate)).status_code == 409
    for body in [
        {"platform": "bluesky", "handle": "not a handle"},
        {"platform": "mastodon", "handle": "sbrank"},
        {"platform": "x", "handle": "sbrank"},
        {"platform": "bluesky", "handle": "sbr.bsky.social", "extra_queries": ["a"] * 6},
        {"platform": "bluesky", "handle": "sbr.bsky.social", "extra_queries": ["x"]},
        {"platform": "bluesky", "handle": "sbr.bsky.social", "label": "x" * 101},
    ]:
        assert (await client.post(URL, json=body)).status_code == 422, body
    edited = await client.put(
        f"{URL}/{row['id']}",
        json={"platform": "mastodon", "handle": "sbrank@mastodon.social", "enabled": False},
    )
    assert edited.status_code == 200 and edited.json()["enabled"] is False
    moved = {"platform": "mastodon", "handle": "other@mastodon.social"}
    assert (await client.put(f"{URL}/{row['id']}", json=moved)).status_code == 422
    listed = (await client.get(URL)).json()
    assert [item["id"] for item in listed["items"]] == [row["id"]]
    assert (await client.delete(f"{URL}/{row['id']}")).status_code == 204
    assert (await client.get(f"{URL}/{row['id']}/candidates")).status_code == 404
    async with api.sessions() as session:
        actions = set((await session.scalars(select(AuditLog.action))).all())
    assert {"social_accounts.add", "social_accounts.update", "social_accounts.remove"} <= actions


async def test_viewer_cannot_write_and_foreign_project_is_hidden(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("vic", ("viewer",))
    client = await login("vic")
    assert (await client.get(URL)).status_code == 200
    body = {"platform": "bluesky", "handle": "sbr.bsky.social"}
    assert (await client.post(URL, json=body)).status_code == 403
    async with api.sessions.begin() as session:
        await repo.upsert_project(session, api.rules.model_copy(update={"project": "other"}))
        row = ProtectedAccount(
            project_id="other",
            platform="bluesky",
            handle="secret.bsky.social",
            created_at=api.clock(),
            next_check_at=api.clock(),
        )
        session.add(row)
        await session.flush()
        foreign = row.id
    assert (await client.get(URL)).json()["items"] == []
    assert (await client.get(f"{URL}/{foreign}/candidates")).status_code == 404


async def test_candidates_show_signals_alerts_gone_and_allowed(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    client = await login()
    row = (
        await client.post(
            URL,
            json={
                "platform": "bluesky",
                "handle": "sbrank.bsky.social",
                "allowed_accounts": ["did:plc:fan"],
            },
        )
    ).json()
    now = api.clock()
    async with api.sessions.begin() as session:
        entity = await repo.upsert_entity(
            session, "url", "https://bsky.app/profile/did:plc:bad", now
        )
        up = await repo.upsert_finding(
            session,
            project_id=api.rules.project,
            entity=entity,
            score=Score(75, Severity.HIGH, Category.IMPERSONATION_ACCOUNT, {"avatar": 40}),
            match={},
            source="social_accounts",
            now=now,
        )
        alert = await repo.open_alert(session, up.finding, Severity.HIGH, now)
        for did, score, gone, finding in [
            ("did:plc:bad", 75, now, up.finding.id),
            ("did:plc:fan", 25, None, None),
        ]:
            session.add(
                AccountCandidate(
                    protected_id=row["id"],
                    platform_account_id=did,
                    handle=f"{did[8:]}.bsky.social",
                    display_name="Sample Brand",
                    profile_url=f"https://bsky.app/profile/{did}",
                    registered_at=now - timedelta(days=3),
                    score=score,
                    signals={"breakdown": {"display_same": 20, "avatar": 40}},
                    finding_id=finding,
                    first_seen=now,
                    last_seen=now,
                    gone_at=gone,
                )
            )
    items = (await client.get(f"{URL}/{row['id']}/candidates")).json()["items"]
    bad, fan = sorted(items, key=lambda i: -i["score"])
    assert bad["severity"] == "high" and bad["alert_id"] == alert.id and bad["gone_at"]
    assert bad["signals"] == ["display_same", "avatar"]
    assert fan["severity"] == "low" and fan["alert_id"] is None and fan["allowed"] is True
    only_high = (
        await client.get(f"{URL}/{row['id']}/candidates", params={"severity": "medium"})
    ).json()["items"]
    assert [i["platform_account_id"] for i in only_high] == ["did:plc:bad"]
    assert (await client.get(URL)).json()["items"][0]["candidate_count"] == 2
    url = f"{URL}/{row['id']}/candidates"
    second = (await client.get(url, params={"page": 2, "limit": 1, "order": "score_desc"})).json()
    assert second["total"] == 2 and second["items"][0]["platform_account_id"] == "did:plc:fan"
    filtered = (
        await client.get(
            url, params={"page": 1, "limit": 1, "severity": "medium", "order": "score_asc"}
        )
    ).json()
    assert filtered["total"] == 1 and filtered["items"][0]["platform_account_id"] == "did:plc:bad"
    assert (await client.get(url, params={"cursor": 1, "order": "score_desc"})).status_code == 422


async def test_adapter_ready_follows_connector_approval(
    api: Any, make_user: Any, login: Any
) -> None:
    # 分析员看页面；合规官批准、平台管理员启用适配器
    await make_user("ops", ("analyst", "compliance_officer", "platform_admin"))
    client = await login("ops")
    row = (await client.post(URL, json={"platform": "bluesky", "handle": "sbr.bsky.social"})).json()
    assert row["adapter_ready"] is False
    approve = await client.put(
        "/api/v1/connectors/social_bluesky/approval",
        json={"license_approved": True, "license_ref": "LEGAL-1"},
    )
    assert approve.status_code == 200, approve.text
    enable = await client.put(
        "/api/v1/connectors/social_bluesky/config",
        json={"enabled": True, "plan": "free", "config": {}},
    )
    assert enable.status_code == 200, enable.text
    assert (await client.get(URL)).json()["items"][0]["adapter_ready"] is True


async def test_manual_check_queue_errors_and_pause(
    api: Any, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_user()
    client = await login()
    row = (await client.post(URL, json={"platform": "bluesky", "handle": "sbr.bsky.social"})).json()
    check = f"{URL}/{row['id']}/check"
    assert (await client.post(check)).status_code == 503
    api.deps.settings = replace(api.deps.settings, broker_url="redis://localhost:6379/0")
    queued: list[int] = []

    async def enqueue(account_id: int) -> None:
        queued.append(account_id)

    monkeypatch.setattr(check_protected_account, "kiq", enqueue)
    assert (await client.post(check)).status_code == 202 and queued == [row["id"]]
    async with api.sessions.begin() as session:
        account = await session.get(ProtectedAccount, row["id"])
        assert account is not None
        account.scan_started_at = api.clock()
    assert (await client.post(check)).status_code == 409
    await client.put(
        f"{URL}/{row['id']}",
        json={"platform": "bluesky", "handle": "sbr.bsky.social", "enabled": False},
    )
    assert (await client.post(check)).status_code == 409
    async with api.sessions() as session:
        actions = set((await session.scalars(select(AuditLog.action))).all())
    assert "social_accounts.check_requested" in actions
