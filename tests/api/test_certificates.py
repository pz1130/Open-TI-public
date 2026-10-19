from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from opti.db import repo
from opti.db.models import Alert, AuditLog, CertificateMonitor, MonitoredCertificate
from opti.pipeline import certificates
from opti.pipeline.tasks import check_certificate_monitor

pytestmark = pytest.mark.db


async def test_crud_validation_and_scope(api: Any, make_user: Any, login: Any) -> None:
    await make_user()
    client = await login()
    added = await client.post(
        "/api/v1/certificate-monitors",
        json={"root_domain": " SBR.INT. ", "known_domains": ["www.sbr.int"]},
    )
    assert added.status_code == 201, added.text
    row = added.json()
    assert row["root_domain"] == "sbr.int" and row["warn_days"] == 30 and row["host_count"] == 0
    assert (
        await client.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    ).status_code == 409
    for body in [
        {"root_domain": "*.sbr.int"},
        {"root_domain": "sbr.int", "known_domains": ["notsbr.int"]},
        {"root_domain": "sbr.int", "warn_days": 0},
    ]:
        assert (await client.post("/api/v1/certificate-monitors", json=body)).status_code == 422
    listed = (await client.get("/api/v1/certificate-monitors")).json()
    assert len(listed["items"]) == 1
    edited = await client.put(
        f"/api/v1/certificate-monitors/{row['id']}",
        json={"root_domain": "sbr.int", "warn_days": 14, "enabled": False},
    )
    assert (
        edited.status_code == 200
        and edited.json()["warn_days"] == 14
        and not edited.json()["enabled"]
    )
    assert (
        await client.put(
            f"/api/v1/certificate-monitors/{row['id']}", json={"root_domain": "other.com"}
        )
    ).status_code == 422
    async with api.sessions.begin() as session:
        session.add(MonitoredCertificate(monitor_id=row["id"], domain="www.sbr.int", state="error"))
    assert (await client.delete(f"/api/v1/certificate-monitors/{row['id']}")).status_code == 204
    assert (await client.get(f"/api/v1/certificate-monitors/{row['id']}/hosts")).status_code == 404
    async with api.sessions() as session:
        assert await session.scalar(select(MonitoredCertificate.id)) is None
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert {"certificates.add", "certificates.update", "certificates.remove"} <= set(actions)


async def test_viewer_cannot_write_and_foreign_project_is_hidden(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("vic", ("viewer",))
    client = await login("vic")
    assert (await client.get("/api/v1/certificate-monitors")).status_code == 200
    assert (
        await client.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    ).status_code == 403
    async with api.sessions.begin() as session:
        await repo.upsert_project(
            session, api.rules.model_copy(update={"project": "other-project"})
        )
        row = CertificateMonitor(
            project_id="other-project",
            root_domain="secret.example",
            created_at=api.clock(),
            next_check_at=api.clock(),
        )
        session.add(row)
        await session.flush()
        foreign_id = row.id
    assert (await client.get("/api/v1/certificate-monitors")).json()["items"] == []
    assert (await client.get(f"/api/v1/certificate-monitors/{foreign_id}/hosts")).status_code == 404


async def test_hosts_use_current_expiry_and_keep_stale_information_on_failure(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    client = await login()
    row = (
        await client.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    ).json()
    now = api.clock()
    end = now + timedelta(days=5)
    cert = {"present": True, "not_after": end.isoformat(), "issuer_o": "Test CA"}
    async with api.sessions.begin() as session:
        session.add_all(
            [
                MonitoredCertificate(
                    monitor_id=row["id"],
                    domain="www.sbr.int",
                    state="healthy",
                    checked_at=now,
                    certificate_checked_at=now,
                    not_after=end,
                    certificate=cert,
                ),
                MonitoredCertificate(
                    monitor_id=row["id"],
                    domain="api.sbr.int",
                    state="error",
                    checked_at=now,
                    certificate_checked_at=now,
                    not_after=end,
                    certificate=cert,
                    error="TimeoutError",
                ),
            ]
        )
    page = (
        await client.get(f"/api/v1/certificate-monitors/{row['id']}/hosts", params={"limit": 1})
    ).json()
    assert page["items"][0]["state"] == "expiring" and page["items"][0]["days_remaining"] == 5
    last = (
        await client.get(
            f"/api/v1/certificate-monitors/{row['id']}/hosts",
            params={"cursor": page["next_cursor"]},
        )
    ).json()["items"][0]
    assert last["state"] == "error" and last["days_remaining"] is None and last["not_after"]
    assert (await client.get("/api/v1/certificate-monitors")).json()["items"][0]["host_count"] == 2
    ordered = (
        await client.get(
            f"/api/v1/certificate-monitors/{row['id']}/hosts",
            params={"page": 2, "limit": 1, "order": "expiry_asc"},
        )
    ).json()
    assert ordered["total"] == 2 and ordered["items"][0]["state"] == "error"
    assert (
        await client.get(
            f"/api/v1/certificate-monitors/{row['id']}/hosts",
            params={"cursor": 1, "order": "expiry_asc"},
        )
    ).status_code == 422


async def test_manual_check_queue_errors_and_pause(
    api: Any, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_user()
    client = await login()
    row = (
        await client.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    ).json()
    url = f"/api/v1/certificate-monitors/{row['id']}/check"
    assert (await client.post(url)).status_code == 503
    api.deps.settings = replace(api.deps.settings, broker_url="redis://localhost:6379/0")
    queued: list[int] = []

    async def enqueue(monitor_id: int) -> None:
        queued.append(monitor_id)

    monkeypatch.setattr(check_certificate_monitor, "kiq", enqueue)
    assert (await client.post(url)).status_code == 202 and queued == [row["id"]]
    async with api.sessions.begin() as session:
        monitor = await session.get(CertificateMonitor, row["id"])
        monitor.scan_started_at = api.clock()
    assert (await client.post(url)).status_code == 409
    await client.put(
        f"/api/v1/certificate-monitors/{row['id']}",
        json={"root_domain": "sbr.int", "enabled": False},
    )
    assert (await client.post(url)).status_code == 409


async def test_hosts_failing_for_30_days_show_as_retired(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    client = await login()
    row = (
        await client.post(
            "/api/v1/certificate-monitors",
            json={"root_domain": "sbr.int", "known_domains": ["mail.sbr.int"]},
        )
    ).json()
    long_ago, recent = api.clock() - timedelta(days=31), api.clock() - timedelta(days=2)
    async with api.sessions.begin() as session:
        for domain, since in (("sbr.int", long_ago), ("mail.sbr.int", long_ago),
                              ("www.sbr.int", long_ago), ("vpn.sbr.int", recent)):  # fmt: skip
            session.add(
                MonitoredCertificate(
                    monitor_id=row["id"], domain=domain, state="error",
                    error="ConnectError", failing_since=since,
                )
            )  # fmt: skip
    hosts = (await client.get(f"/api/v1/certificate-monitors/{row['id']}/hosts")).json()["items"]
    # 根域名与手动补充的主机始终检查，不会停查
    assert {h["domain"]: h["state"] for h in hosts} == {
        "sbr.int": "error", "mail.sbr.int": "error",
        "www.sbr.int": "retired", "vpn.sbr.int": "error",
    }  # fmt: skip


async def test_root_domain_must_belong_to_official_domains(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    client = await login()
    url = "/api/v1/certificate-monitors"
    refused = await client.post(url, json={"root_domain": "someone-else.org"})
    assert refused.status_code == 422
    assert "official" in refused.json()["detail"]
    # 官方域名 sbr.int 本身及其子域名可以；只是后缀相同的其他域名不行
    assert (await client.post(url, json={"root_domain": "notsbr.int"})).status_code == 422
    assert (await client.post(url, json={"root_domain": "sbr.int"})).status_code == 201
    assert (await client.post(url, json={"root_domain": "mail.sbr.int"})).status_code == 201


async def test_admin_can_monitor_certificates_and_page_filtered_hosts(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("ops", ("platform_admin",))
    client = await login("ops")
    me = (await client.get("/api/v1/auth/me")).json()
    assert {"certificates:read", "certificates:write"} <= set(me["permissions"])
    assert (await client.get("/api/v1/alerts")).status_code == 403
    monitors = []
    for domain in ("sbr.int", "mail.sbr.int", "web.sbr.int"):
        response = await client.post("/api/v1/certificate-monitors", json={"root_domain": domain})
        assert response.status_code == 201, response.text
        monitors.append(response.json())
    second = (
        await client.get("/api/v1/certificate-monitors", params={"page": 2, "limit": 2})
    ).json()
    assert second["total"] == 3 and [r["id"] for r in second["items"]] == [monitors[0]["id"]]
    monitor_id = monitors[0]["id"]
    async with api.sessions.begin() as session:
        session.add_all(
            [
                MonitoredCertificate(monitor_id=monitor_id, domain=d)
                for d in ("api.sbr.int", "mail.sbr.int", "mail2.sbr.int")
            ]
        )
    url = f"/api/v1/certificate-monitors/{monitor_id}/hosts"
    filtered = (await client.get(url, params={"page": 2, "limit": 1, "q": "mail"})).json()
    assert filtered["total"] == 2 and filtered["items"][0]["domain"] == "mail2.sbr.int"
    empty = (await client.get(url, params={"page": 4, "limit": 1})).json()
    assert empty["total"] == 3 and empty["items"] == []
    assert (await client.get(url, params={"page": 1, "cursor": 1})).status_code == 422
    assert (
        await client.put(
            f"/api/v1/certificate-monitors/{monitor_id}",
            json={"root_domain": "sbr.int", "warn_days": 14},
        )
    ).status_code == 200
    assert (await client.delete(f"/api/v1/certificate-monitors/{monitor_id}")).status_code == 204


async def test_only_admin_can_approve_discoveries_and_set_host_threshold(
    api: Any,
    make_user: Any,
    login: Any,
) -> None:
    await make_user()
    await make_user("ops", ("platform_admin",))
    analyst, admin = await login(), await login("ops")
    monitor = (
        await analyst.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    ).json()
    base = f"/api/v1/certificate-monitors/{monitor['id']}/hosts"
    async with api.sessions.begin() as s:
        row = MonitoredCertificate(monitor_id=monitor["id"], domain="www.sbr.int")
        s.add(row)
        await s.flush()
        hid = row.id
    host = (await analyst.get(base)).json()["items"][0]
    assert not host["approved"] and host["warn_days"] is None and host["effective_warn_days"] == 30
    assert (await analyst.put(f"{base}/{hid}", json={"approved": True})).status_code == 403
    for bad in (0, 366, True):
        assert (
            await admin.put(f"{base}/{hid}", json={"approved": True, "warn_days": bad})
        ).status_code == 422
    assert (
        await admin.put(f"{base}/{hid}", json={"approved": True, "warn_days": 14})
    ).status_code == 204
    assert (await admin.get(base, params={"approval": "pending", "page": 1})).json()["total"] == 0
    host = (await analyst.get(base, params={"approval": "approved", "page": 1})).json()["items"][0]
    assert host["approved"] and host["approved_at"] and host["effective_warn_days"] == 14
    async with api.sessions() as s:
        row = await s.get(MonitoredCertificate, hid)
        assert row.approved_by is not None
    assert (await admin.put(f"{base}/{hid + 1}", json={"approved": True})).status_code == 404
    other = (
        await admin.post("/api/v1/certificate-monitors", json={"root_domain": "api.sbr.int"})
    ).json()
    assert (
        await admin.put(
            f"/api/v1/certificate-monitors/{other['id']}/hosts/{hid}", json={"approved": True}
        )
    ).status_code == 404
    assert (await admin.put(f"{base}/{hid}", json={"approved": False})).status_code == 204
    host = (await analyst.get(base)).json()["items"][0]
    assert not host["approved"] and host["effective_warn_days"] == 30
    async with api.sessions() as s:
        assert (
            len(
                (
                    await s.scalars(
                        select(AuditLog).where(AuditLog.action == "certificates.host_configured")
                    )
                ).all()
            )
            == 2
        )


async def test_revoking_certificate_approval_closes_alert_and_reapproval_can_alert_again(
    api: Any,
    make_user: Any,
    login: Any,
) -> None:
    await make_user("ops", ("platform_admin",))
    admin = await login("ops")
    monitor = (
        await admin.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    ).json()
    mid = monitor["id"]
    async with api.sessions.begin() as s:
        host = MonitoredCertificate(monitor_id=mid, domain="www.sbr.int")
        s.add(host)
        await s.flush()
        hid = host.id
    url = f"/api/v1/certificate-monitors/{mid}/hosts/{hid}"
    assert (await admin.put(url, json={"approved": True})).status_code == 204
    scan = certificates.Scan(mid, api.rules.project, "sbr.int", 30, (), api.clock())
    data = {
        "present": True,
        "sha256": "first",
        "not_after": (api.clock() + timedelta(days=2)).isoformat(),
    }
    async with api.sessions.begin() as s:
        await certificates._alert(s, scan, "www.sbr.int", data, api.clock())
    assert (await admin.put(url, json={"approved": False})).status_code == 204
    async with api.sessions() as s:
        rows = (await s.scalars(select(Alert))).all()
        assert len(rows) == 1 and rows[0].status == "closed" and rows[0].closed_at
    assert (await admin.put(url, json={"approved": True})).status_code == 204
    async with api.sessions.begin() as s:
        await certificates._alert(s, scan, "www.sbr.int", data, api.clock())
    async with api.sessions() as s:
        assert (await s.scalars(select(Alert.status).order_by(Alert.id))).all() == [
            "closed",
            "open",
        ]


async def test_root_only_creation_queues_discovery_after_commit_and_keeps_monitor_on_queue_failure(
    api: Any,
    make_user: Any,
    login: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await make_user()
    client = await login()
    api.deps.settings = replace(api.deps.settings, broker_url="redis://localhost:6379/0")
    queued: list[int] = []

    async def enqueue(mid: int) -> None:
        # Worker 可以立即拿到已提交的根域名，不存在先入队后提交的竞态。
        async with api.sessions() as s:
            monitor = await s.get(CertificateMonitor, mid)
            assert monitor is not None and monitor.known_domains == []
        queued.append(mid)

    monkeypatch.setattr(check_certificate_monitor, "kiq", enqueue)
    created = await client.post("/api/v1/certificate-monitors", json={"root_domain": "sbr.int"})
    assert created.status_code == 201 and queued == [created.json()["id"]]

    async def unavailable(mid: int) -> None:
        raise ConnectionError("queue down")

    monkeypatch.setattr(check_certificate_monitor, "kiq", unavailable)
    created = await client.post("/api/v1/certificate-monitors", json={"root_domain": "api.sbr.int"})
    assert created.status_code == 201
    async with api.sessions() as s:
        monitor = await s.get(CertificateMonitor, created.json()["id"])
        assert monitor is not None and monitor.next_check_at == api.clock()
    paused = await client.post(
        "/api/v1/certificate-monitors", json={"root_domain": "mail.sbr.int", "enabled": False}
    )
    assert paused.status_code == 201 and len(queued) == 1
