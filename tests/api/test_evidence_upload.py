import io
import json
import threading
import zipfile
from typing import Any

import pytest
from PIL import Image
from sqlalchemy import select

from opti.db import repo
from opti.db.models import Alert, AuditLog, Evidence, Finding

pytestmark = pytest.mark.db
HEADERS = {"Content-Type": "image/png"}


def _png(seed: int) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (10 + seed, 10), (seed % 256, 0, 0)).save(out, format="PNG")
    return out.getvalue()


async def test_analyst_uploads_screenshot(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    r = await c.post(f"/api/v1/alerts/{a.alert_id}/evidence", content=_png(1), headers=HEADERS)
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["kind"] == "upload" and ev["content_type"] == "image/png"
    assert ev["uploaded_by"] == "alice" and ev["node_id"] == "upload"
    assert ev["method"] == "analyst-upload" and len(ev["original_sha256"]) == 64
    content = await c.get(f"/api/v1/evidence/{ev['id']}/content")
    assert content.status_code == 200 and content.headers["x-content-sha256"] == ev["sha256"]
    detail = (await c.get(f"/api/v1/alerts/{a.alert_id}")).json()
    assert [e["uploaded_by"] for e in detail["evidence"]] == ["alice"]
    async with api.sessions() as s:
        row = await s.scalar(select(AuditLog).where(AuditLog.action == "evidence.upload"))
    assert row is not None and row.detail["alert_id"] == a.alert_id
    assert row.detail["sha256"] == ev["sha256"]


async def test_upload_errors(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    url = f"/api/v1/alerts/{a.alert_id}/evidence"
    assert (
        await c.post(url, content=_png(1), headers={"Content-Type": "image/gif"})
    ).status_code == 415
    assert (
        await c.post(
            url, content=b"\x89PNG\r\n\x1a\n" + b"\0" * (10 * 1024 * 1024), headers=HEADERS
        )
    ).status_code == 413
    assert (
        await c.post("/api/v1/alerts/999999/evidence", content=_png(1), headers=HEADERS)
    ).status_code == 404
    for name, role in (("vic", "viewer"), ("rob", "responder"), ("aud", "auditor")):
        await make_user(name, (role,))
        assert (
            await (await login(name)).post(url, content=_png(1), headers=HEADERS)
        ).status_code == 403
    api.app.state.deps.store = None
    assert (await c.post(url, content=_png(1), headers=HEADERS)).status_code == 503


async def test_superseded_alert_rejects_upload(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await seed_alert()
    async with api.sessions.begin() as s:
        alert = await s.get(Alert, a.alert_id)
        assert alert is not None
        alert.status = "superseded"
    await make_user("alice", ("analyst",))
    c = await login("alice")
    r = await c.post(f"/api/v1/alerts/{a.alert_id}/evidence", content=_png(1), headers=HEADERS)
    assert r.status_code == 409 and r.json()["detail"] == "alert superseded by a newer alert"
    assert api.store.objects == {}  # 被拒的上传不写对象存储


async def test_other_project_alert_is_not_found(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await seed_alert()
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, api.rules.model_copy(update={"project": "another"}))
        alert, finding = await s.get(Alert, a.alert_id), await s.get(Finding, a.finding_id)
        assert alert is not None and finding is not None
        alert.project_id = finding.project_id = "another"
    await make_user("alice", ("analyst",))
    c = await login("alice")
    r = await c.post(f"/api/v1/alerts/{a.alert_id}/evidence", content=_png(1), headers=HEADERS)
    assert r.status_code == 404
    assert api.store.objects == {}  # 先确认告警归属，不写对象存储


async def test_bundle_manifest_keeps_upload_chain(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    ev = (
        await c.post(f"/api/v1/alerts/{a.alert_id}/evidence", content=_png(3), headers=HEADERS)
    ).json()
    r = await c.get(f"/api/v1/alerts/{a.alert_id}/evidence-bundle")
    assert r.status_code == 200, r.text
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(r.content)).read("manifest.json"))
    [entry] = manifest["evidence"]
    assert entry["uploaded_by"] == "alice" and entry["original_sha256"] == ev["original_sha256"]


async def test_limit_per_alert_cleans_up_object(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    url = f"/api/v1/alerts/{a.alert_id}/evidence"
    for i in range(20):
        assert (await c.post(url, content=_png(i), headers=HEADERS)).status_code == 201
    before = set(api.store.objects)
    assert (await c.post(url, content=_png(99), headers=HEADERS)).status_code == 409
    assert set(api.store.objects) == before


async def test_failed_upload_keeps_object_shared_with_other_evidence(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    first, full = await seed_alert(domain="sbr-a.top"), await seed_alert(domain="sbr-b.top")
    await make_user("alice", ("analyst",))
    c = await login("alice")
    shared = _png(7)
    ok = await c.post(f"/api/v1/alerts/{first.alert_id}/evidence", content=shared, headers=HEADERS)
    assert ok.status_code == 201
    for i in range(20):
        assert (
            await c.post(
                f"/api/v1/alerts/{full.alert_id}/evidence",
                content=_png(100 + i),
                headers=HEADERS,
            )
        ).status_code == 201
    assert (
        await c.post(f"/api/v1/alerts/{full.alert_id}/evidence", content=shared, headers=HEADERS)
    ).status_code == 409
    async with api.sessions() as s:
        key = await s.scalar(select(Evidence.object_key).where(Evidence.id == ok.json()["id"]))
    assert key in api.store.objects


async def test_image_processing_runs_off_the_event_loop(
    api: Any, make_user: Any, login: Any, seed_alert: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opti.api.routes import evidence as route

    threads: list[str] = []
    real = route.clean_image

    def spy(data: bytes, declared: str) -> Any:
        threads.append(threading.current_thread().name)
        return real(data, declared)

    monkeypatch.setattr(route, "clean_image", spy)
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    assert (
        await c.post(f"/api/v1/alerts/{a.alert_id}/evidence", content=_png(1), headers=HEADERS)
    ).status_code == 201
    assert threads and threads[0] != threading.main_thread().name  # 解码与重编码不能阻塞事件循环


async def test_cleanup_failure_keeps_original_error(
    api: Any, make_user: Any, login: Any, seed_alert: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    url = f"/api/v1/alerts/{a.alert_id}/evidence"
    for i in range(20):
        assert (await c.post(url, content=_png(i), headers=HEADERS)).status_code == 201

    async def broken(key: str, version_id: str | None = None) -> None:
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(api.store, "delete", broken)
    r = await c.post(url, content=_png(99), headers=HEADERS)
    assert (
        r.status_code == 409
        and r.json()["detail"] == "too many uploaded screenshots for this alert"
    )
