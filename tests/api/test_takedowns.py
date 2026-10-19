import email
import email.policy
import hashlib
import io
import zipfile
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.db import repo
from opti.db.models import Alert, AuditLog, DomainObservation, Entity, Evidence, WatchedDomain
from opti.organization import Organization
from opti.pipeline import watchlist
from opti.pipeline.enrichment import EnrichmentService
from opti.sdk.testing import make_context, static_enricher
from opti.takedown import service as takedown_service
from opti.takedown.config import load_takedown_config

pytestmark = pytest.mark.db
REPO = Path(__file__).resolve().parents[2]
ORG = Organization(
    name="Example Organization", short_name="Example", website="https://www.example.org",
    legal_statement="授权声明。", legal_statement_en="We are authorized.",
    takedown_sender="abuse-response@example.org", signature="Example Security Team",
)  # fmt: skip
REGISTRAR = "registrar:cheap-registrar-llc"


def _cached(data: dict[str, Any]) -> dict[str, Any]:
    return {"data": data, "fetched_at": datetime.now(UTC).isoformat()}


async def _prepare(
    api: Any, seed_alert: Callable[..., Awaitable[Any]], domain: str = "sbr-loans.com"
) -> Any:
    a = await seed_alert(domain)
    async with api.sessions.begin() as s:
        e = await s.get(Entity, a.entity_id)
        e.enrichment = {
            "rdap": _cached({"registrar": "Cheap Registrar LLC", "abuse_email": "abuse@registrar.example",
                             "nameservers": ["ns1.host.example"]}),
            "dns": _cached({"a": ["45.33.32.156"]}),
        }  # fmt: skip
        ip = await repo.upsert_entity(s, "ip", "45.33.32.156", api.clock())
        ip.enrichment = {"ip_rdap": _cached({"found": True, "network_name": "LINODE-US", "handle": "NET-45-33",
                                             "org": "Akamai Connected Cloud", "abuse_email": "abuse@linode.example"})}  # fmt: skip
    deps = api.app.state.deps
    deps.config = ConfigRuntime.static(deps.rules, ORG, sessions=deps.sessions)
    override(
        deps.config, takedown=load_takedown_config(REPO / "config" / "takedown" / "platforms.yaml")
    )
    deps.templates_dir = REPO / "config" / "takedown" / "templates"
    return a


async def test_targets_and_full_flow(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await _prepare(api, seed_alert)
    await make_user("alice", ("analyst",))
    await make_user("bob", ("responder",))
    await make_user("vic", ("viewer",))
    alice, bob = await login("alice"), await login("bob")

    r = await alice.get(f"/api/v1/alerts/{a.alert_id}/takedown-targets")
    assert r.status_code == 200, r.text
    ids = [t["id"] for t in r.json()["targets"]]
    assert ids[:2] == [REGISTRAR, "hosting:net-45-33"] and "report:google_safe_browsing" in ids
    assert r.json()["missing_hosting"] == []

    r = await alice.post(
        f"/api/v1/alerts/{a.alert_id}/takedowns", json={"target_id": REGISTRAR, "language": "zh-CN"}
    )
    assert r.status_code == 201, r.text
    td = r.json()
    assert td["state"] == "draft" and td["created_by"] == "alice"
    assert td["target"]["email"] == "abuse@registrar.example"
    assert "sbr-loans[.]com" in td["subject"] and "Example Organization" in td["body"]
    tid = td["id"]

    assert (await alice.get(f"/api/v1/takedowns/{tid}/eml")).status_code == 409  # 未审批
    assert (
        await alice.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    ).status_code == 403
    r = await bob.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    assert r.status_code == 200 and r.json()["approved_by"] == "bob"

    r = await alice.get(f"/api/v1/takedowns/{tid}/eml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("message/rfc822")
    msg = email.message_from_bytes(r.content, policy=email.policy.default)
    assert msg["To"] == "abuse@registrar.example" and msg["X-Unsent"] == "1"

    r = await alice.post(
        f"/api/v1/takedowns/{tid}/transition", json={"to": "submitted", "external_ref": "CASE-9"}
    )
    assert r.json()["state"] == "submitted" and r.json()["due_at"] is not None
    detail = (await alice.get(f"/api/v1/takedowns/{tid}")).json()
    assert [e["to_state"] for e in detail["events"]] == ["draft", "approved", "submitted"]
    assert detail["escalation"][0]["basis"] == "escalation"
    alert = (await alice.get(f"/api/v1/alerts/{a.alert_id}")).json()
    assert [(t["id"], t["state"], t["target_kind"]) for t in alert["takedowns"]] == [
        (tid, "submitted", "registrar")
    ]
    page = (await bob.get("/api/v1/takedowns", params={"state": ["submitted"]})).json()
    assert [t["id"] for t in page["items"]] == [tid]

    assert (await (await login("vic")).get("/api/v1/takedowns")).status_code == 403
    async with api.sessions() as s:
        actions = (
            await s.scalars(
                select(AuditLog.action)
                .where(AuditLog.action.like("takedown.%"))
                .order_by(AuditLog.id)
            )
        ).all()
    assert list(actions) == [
        "takedown.create",
        "takedown.transition",
        "takedown.export_eml",
        "takedown.transition",
    ]


async def test_four_eyes_over_api(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await _prepare(api, seed_alert)
    await make_user("bob", ("responder",))
    await make_user("carol", ("compliance_officer",))
    bob, carol = await login("bob"), await login("carol")
    tid = (
        await bob.post(f"/api/v1/alerts/{a.alert_id}/takedowns", json={"target_id": REGISTRAR})
    ).json()["id"]
    r = await bob.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    assert r.status_code == 403 and "four-eyes" in r.json()["detail"]
    assert (
        await carol.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    ).status_code == 200
    r = await bob.patch(
        f"/api/v1/takedowns/{tid}", json={"subject": "Changed", "body": "changed body\n"}
    )
    assert r.status_code == 200 and r.json()["state"] == "draft" and r.json()["approved_by"] is None
    assert (await bob.get(f"/api/v1/takedowns/{tid}/eml")).status_code == 409


async def test_create_validation(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await _prepare(api, seed_alert)
    await make_user("alice", ("analyst",))
    await make_user("bob", ("responder",))
    alice, bob = await login("alice"), await login("bob")
    url = f"/api/v1/alerts/{a.alert_id}/takedowns"
    assert (
        await alice.post(url, json={"target_id": "registrar:evil"})
    ).status_code == 422  # 只接受服务端发现的对象
    assert (
        await alice.post("/api/v1/alerts/999999/takedowns", json={"target_id": REGISTRAR})
    ).status_code == 404
    assert (
        await alice.post(url, json={"target_id": REGISTRAR, "language": "fr-FR"})
    ).status_code == 422
    assert (await alice.post(url, json={"target_id": REGISTRAR})).status_code == 201
    assert (
        await alice.post(url, json={"target_id": REGISTRAR})
    ).status_code == 409  # 进行中的重复投诉
    # 网页表单渠道没有邮箱：可以起草、审批，但不能导出 .eml
    tid = (await alice.post(url, json={"target_id": "report:google_safe_browsing"})).json()["id"]
    assert (
        await bob.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    ).status_code == 200
    assert (await alice.get(f"/api/v1/takedowns/{tid}/eml")).status_code == 409


async def test_evidence_bundle_endpoint(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await _prepare(api, seed_alert)
    await make_user("alice", ("analyst",))
    await make_user("vic", ("viewer",))
    alice = await login("alice")
    png = b"\x89PNG\r\n\x1a\n" + b"1" * 50
    await api.store.put("ev/a.png", png, "image/png")
    async with api.sessions.begin() as s:
        s.add(
            Evidence(
                finding_id=a.finding_id, alert_id=a.alert_id, kind="screenshot", object_key="ev/a.png",
                sha256=hashlib.sha256(png).hexdigest(), size=len(png), content_type="image/png",
                captured_at=api.clock(), node_id="hk1", method="test", source_url="https://sbr-loans.com/",
            )
        )  # fmt: skip
    r = await alice.get(f"/api/v1/alerts/{a.alert_id}/evidence-bundle")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert any(
        n.endswith("-screenshot.png") for n in zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    )
    assert (
        await (await login("vic")).get(f"/api/v1/alerts/{a.alert_id}/evidence-bundle")
    ).status_code == 403
    async with api.sessions.begin() as s:
        await s.execute(update(Evidence).values(sha256="0" * 64))
    assert (await alice.get(f"/api/v1/alerts/{a.alert_id}/evidence-bundle")).status_code == 409


async def test_stats_endpoint(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await _prepare(api, seed_alert)
    await make_user("alice", ("analyst",))
    await make_user("bob", ("responder",))
    alice, bob = await login("alice"), await login("bob")
    tid = (
        await alice.post(f"/api/v1/alerts/{a.alert_id}/takedowns", json={"target_id": REGISTRAR})
    ).json()["id"]
    await bob.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    await alice.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "submitted"})
    api.clock.now += timedelta(hours=6)
    await alice.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "removed"})
    stats = (await alice.get("/api/v1/takedowns/stats")).json()
    assert stats["by_state"] == {"removed": 1} and stats["mttr_hours"] is not None
    assert (
        stats["targets"][0]["name"] == "Cheap Registrar LLC"
        and stats["targets"][0]["median_response_hours"] == 6.0
    )


async def test_lifecycle_removed_then_reappears(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await _prepare(api, seed_alert)
    await make_user("alice", ("analyst",))
    await make_user("bob", ("responder",))
    alice, bob = await login("alice"), await login("bob")
    tid = (
        await alice.post(f"/api/v1/alerts/{a.alert_id}/takedowns", json={"target_id": REGISTRAR})
    ).json()["id"]
    await bob.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "approved"})
    await alice.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "submitted"})
    assert (await alice.post(f"/api/v1/takedowns/{tid}/transition", json={"to": "removed"})).json()[
        "state"
    ] == "removed"

    state: dict[str, Any] = {"dns": {"nxdomain": True, "exists": False}}
    ctx = make_context(api.rules)
    svc = EnrichmentService(
        {
            "dns": static_enricher(ctx, "dns", lambda _v: dict(state["dns"])),
            "http_probe": static_enricher(ctx, "http_probe", {"reachable": True, "status": 200, "title": "Welcome",
                                                              "has_password_field": False, "brand_terms": []}),
            "tls": static_enricher(ctx, "tls", {"present": False}),
        },
        clock=api.clock,
    )  # fmt: skip

    async def noop(_s: AsyncSession, _wd: WatchedDomain, _changes: list[str]) -> None:
        return None

    async def recheck() -> list[int]:
        api.clock.now += timedelta(hours=4)
        async with api.sessions.begin() as s:
            wd = await s.scalar(
                select(WatchedDomain).where(WatchedDomain.domain == "sbr-loans.com")
            )
            assert wd is not None and wd.expires_at is not None
            obs: DomainObservation = await watchlist.recheck(
                s, wd, enrichment=svc, on_change=noop, now=api.clock()
            )
            return await takedown_service.on_recheck(s, wd, obs, now=api.clock())

    assert await recheck() == []  # 下架后确认已不存在
    assert await recheck() == []
    state["dns"] = {"exists": True, "a": ["45.33.32.156"]}  # 复活：又能解析、页面可访问
    [new_alert] = await recheck()
    alice = await login("alice")  # rechecks advance beyond the login session lifetime
    detail = (await alice.get(f"/api/v1/takedowns/{tid}")).json()["takedown"]
    assert detail["state"] == "reappeared" and detail["reappeared_alert_id"] == new_alert
    alert = (await alice.get(f"/api/v1/alerts/{new_alert}")).json()
    assert alert["alert"]["status"] == "open" and alert["alert"]["severity"] == "high"
    assert [t["state"] for t in alert["takedowns"]] == ["reappeared"]  # 新告警能看到原投诉
    assert await recheck() == []  # 只触发一次
    async with api.sessions() as s:
        assert (await s.get(Alert, a.alert_id)).status == "superseded"  # type: ignore[union-attr]
