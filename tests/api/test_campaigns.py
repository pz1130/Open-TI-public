from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import func, select, update

from opti.db.models import Alert, AuditLog, Campaign, Entity, Feedback, SuppressionRule
from opti.pipeline.campaigns import CampaignConfig, recompute

pytestmark = pytest.mark.db
UserFactory = Callable[..., Awaitable[int]]
IP = "93.184.216.34"


async def _with_ip(api: Any, seeded: Any, ip: str = IP) -> None:
    async with api.sessions.begin() as s:
        entity = await s.get(Entity, seeded.entity_id)
        assert entity is not None
        entity.enrichment = {"dns": {"data": {"a": [ip]}}}


async def _recompute(api: Any) -> None:
    async with api.sessions.begin() as s:
        await recompute(s, api.rules.project, CampaignConfig(), now=api.clock())


async def _actions(api: Any) -> list[str]:
    async with api.sessions() as s:
        return list((await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all())


async def _campaign(api: Any, seed_alert: Any, *domains: str) -> tuple[int, list[Any]]:
    seeded = [await seed_alert(d) for d in domains]
    for item in seeded:
        await _with_ip(api, item)
    await _recompute(api)
    async with api.sessions() as s:
        cid = (await s.scalars(select(Campaign.id))).one()
    return cid, seeded


async def test_list_detail_confirm_and_members(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    cid, (a, _b, c) = await _campaign(api, seed_alert, "sbr-a.top", "sbr-b.top", "sbr-c.top")
    client = await login()
    page = (await client.get("/api/v1/campaigns", params={"state": "candidate"})).json()
    assert page["total"] == 1
    summary = page["items"][0]
    assert summary["id"] == cid and summary["member_count"] == 3 and summary["pending_count"] == 0
    assert summary["active_alerts"] == 3 and summary["top_severity"] == "high"
    assert summary["signal_kinds"] == ["ip"] and summary["label_value"] == "sbr-a.top"
    assert summary["name"] is None
    assert (await client.get("/api/v1/campaigns", params={"state": "confirmed"})).json()[
        "total"
    ] == 0

    detail = (await client.get(f"/api/v1/campaigns/{cid}")).json()
    assert {m["value"] for m in detail["members"]} == {"sbr-a.top", "sbr-b.top", "sbr-c.top"}
    first = next(m for m in detail["members"] if m["finding_id"] == a.finding_id)
    assert first["alert_id"] == a.alert_id and first["status"] == "open"
    assert first["signals"][0]["kind"] == "ip" and first["signals"][0]["value"] == IP

    r = await client.patch(
        f"/api/v1/campaigns/{cid}",
        json={"state": "confirmed", "name": " 贷款诈骗团伙 ", "note": "同一托管"},
    )
    assert r.status_code == 200 and r.json()["state"] == "confirmed"
    assert r.json()["name"] == "贷款诈骗团伙"

    d = await seed_alert("sbr-d.top")
    await _with_ip(api, d)
    await _recompute(api)
    detail = (await client.get(f"/api/v1/campaigns/{cid}")).json()
    assert detail["campaign"]["pending_count"] == 1 and detail["note"] == "同一托管"
    assert detail["confirmed_by"] == "alice"
    url = f"/api/v1/campaigns/{cid}/members"
    assert (
        await client.post(f"{url}/{d.finding_id}", json={"decision": "accept"})
    ).status_code == 200
    assert (
        await client.post(f"{url}/{c.finding_id}", json={"decision": "remove"})
    ).status_code == 200
    assert (
        await client.post(f"{url}/{c.finding_id}", json={"decision": "remove"})
    ).status_code == 409
    assert (await client.post(f"{url}/999999", json={"decision": "remove"})).status_code == 404

    alert_a = (await client.get(f"/api/v1/alerts/{a.alert_id}")).json()
    assert alert_a["campaign"] == {
        "id": cid, "name": "贷款诈骗团伙", "label_value": "sbr-a.top", "member_count": 3,
        "state": "confirmed", "member_state": "member",
    }  # fmt: skip
    assert (await client.get(f"/api/v1/alerts/{c.alert_id}")).json()["campaign"] is None
    actions = await _actions(api)
    assert actions.count("campaign.update") == 1 and actions.count("campaign.member") == 2


async def test_state_transitions(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    cid, _ = await _campaign(api, seed_alert, "sbr-a.top", "sbr-b.top")
    client = await login()
    url = f"/api/v1/campaigns/{cid}"
    assert (await client.patch(url, json={"state": "dismissed"})).json()["state"] == "dismissed"
    assert (await client.patch(url, json={"state": "confirmed"})).status_code == 409
    assert (await client.patch(url, json={"state": "candidate"})).json()["state"] == "candidate"
    assert (await client.patch(url, json={"state": "confirmed"})).json()["state"] == "confirmed"
    assert (await client.patch(url, json={"state": "dismissed"})).status_code == 409
    assert (await client.patch(url, json={"name": "x" * 201})).status_code == 422
    assert (await client.patch(url, json={"color": "red"})).status_code == 422
    assert (await client.get("/api/v1/campaigns/999999")).status_code == 404


async def test_bulk_verdict_only_touches_member_open_alerts(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    cid, (a, b, closed) = await _campaign(api, seed_alert, "sbr-a.top", "sbr-b.top", "sbr-c.top")
    client = await login()
    url = f"/api/v1/campaigns/{cid}/bulk"
    assert (await client.post(url, json={"action": "close"})).status_code == 409  # 候选不能批量
    await client.patch(f"/api/v1/campaigns/{cid}", json={"state": "confirmed"})
    async with api.sessions.begin() as s:
        await s.execute(update(Alert).where(Alert.id == closed.alert_id).values(status="closed"))
    pending = await seed_alert("sbr-p.top")
    await _with_ip(api, pending)
    await _recompute(api)

    assert (await client.post(url, json={"action": "verdict"})).status_code == 422
    bad = {"action": "verdict", "verdict": "false_positive", "suppress": "domain"}
    assert (await client.post(url, json=bad)).status_code == 422
    r = await client.post(
        url, json={"action": "verdict", "verdict": "false_positive", "reason": "同一团伙已处置"}
    )
    assert r.status_code == 200
    assert (
        sorted(r.json()["updated"]) == sorted([a.alert_id, b.alert_id]) and r.json()["skipped"] == 1
    )
    async with api.sessions() as s:
        statuses = dict((await s.execute(select(Alert.id, Alert.status))).all())
        assert statuses[a.alert_id] == statuses[b.alert_id] == "closed"
        assert statuses[pending.alert_id] == "open"  # 待确认成员不受影响
        assert await s.scalar(select(func.count()).select_from(Feedback)) == 2
        assert await s.scalar(select(func.count()).select_from(SuppressionRule)) == 0
        details = list(
            (
                await s.scalars(select(AuditLog.detail).where(AuditLog.action == "alert.feedback"))
            ).all()
        )
        assert all(d["campaign_id"] == cid for d in details) and len(details) == 2
    assert (await _actions(api)).count("campaign.bulk") == 1


async def test_bulk_acknowledge_and_close(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    cid, (a, b) = await _campaign(api, seed_alert, "sbr-a.top", "sbr-b.top")
    client = await login()
    await client.patch(f"/api/v1/campaigns/{cid}", json={"state": "confirmed"})
    await client.patch(f"/api/v1/alerts/{b.alert_id}", json={"status": "acknowledged"})
    url = f"/api/v1/campaigns/{cid}/bulk"
    r = (await client.post(url, json={"action": "acknowledge"})).json()
    assert r == {"updated": [a.alert_id], "skipped": 1}  # 已确认的不重复处理
    r = (await client.post(url, json={"action": "close"})).json()
    assert sorted(r["updated"]) == sorted([a.alert_id, b.alert_id]) and r["skipped"] == 0
    async with api.sessions() as s:
        closed_at = (await s.scalars(select(Alert.closed_at).where(Alert.id == a.alert_id))).one()
        assert closed_at is not None


async def test_permissions(api: Any, make_user: UserFactory, login: Any, seed_alert: Any) -> None:
    await make_user()
    await make_user("vic", ("viewer",))
    await make_user("rob", ("responder",))
    cid, (a, _) = await _campaign(api, seed_alert, "sbr-a.top", "sbr-b.top")
    viewer = await login("vic")
    assert (await viewer.get("/api/v1/campaigns")).status_code == 403
    assert (await viewer.get(f"/api/v1/campaigns/{cid}")).status_code == 403
    responder = await login("rob")
    assert (await responder.get(f"/api/v1/campaigns/{cid}")).status_code == 200
    assert (
        await responder.patch(f"/api/v1/campaigns/{cid}", json={"state": "confirmed"})
    ).status_code == 403
    assert (
        await responder.post(f"/api/v1/campaigns/{cid}/bulk", json={"action": "close"})
    ).status_code == 403
    analyst = await login()
    await analyst.patch(f"/api/v1/campaigns/{cid}", json={"state": "confirmed"})
    assert (await viewer.get(f"/api/v1/alerts/{a.alert_id}")).json()["campaign"] is None
    assert (await responder.get(f"/api/v1/alerts/{a.alert_id}")).json()["campaign"]["id"] == cid
