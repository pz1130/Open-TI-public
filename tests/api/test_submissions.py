import io
from pathlib import Path
from typing import Any

import pytest
from PIL import Image
from sqlalchemy import select

from opti.configs.testing import override
from opti.db.models import Alert, AuditLog
from opti.takedown.config import load_takedown_config

pytestmark = pytest.mark.db
REPO = Path(__file__).resolve().parents[2]
BODY = {
    "url": "https://www.linkedin.com/in/fake-sbr-ceo/",
    "category": "impersonation_account",
    "severity": "high",
    "description": "冒充行长招聘",
}


def _platforms(api: Any) -> None:
    override(
        api.app.state.deps.config,
        takedown=load_takedown_config(REPO / "config" / "takedown" / "platforms.yaml"),
    )


async def test_analyst_submits_and_audit_omits_description(
    api: Any, make_user: Any, login: Any
) -> None:
    _platforms(api)
    await make_user("alice", ("analyst",))
    c = await login("alice")
    r = await c.post("/api/v1/submissions", json=BODY)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["platform"] == "linkedin" and out["created_alert"] is True
    detail = (await c.get(f"/api/v1/alerts/{out['alert_id']}")).json()
    assert detail["finding"]["category"] == "impersonation_account"
    assert detail["alert"]["severity"] == "high"
    async with api.sessions() as s:
        alert = await s.get(Alert, out["alert_id"])
        assert alert is not None and alert.evidence_status == "none"
        row = await s.scalar(select(AuditLog).where(AuditLog.action == "submission.create"))
    assert row is not None and row.detail == {
        "host": "www.linkedin.com",
        "category": "impersonation_account",
        "severity": "high",
        "platform": "linkedin",
    }


async def test_rejected_inputs(api: Any, make_user: Any, login: Any) -> None:
    _platforms(api)
    await make_user("alice", ("analyst",))
    c = await login("alice")
    for change in (
        {"url": "https://www.sbr.int/jobs"},
        {"severity": "low"},
        {"category": "brand_mention"},
        {"description": ""},
        {"extra": 1},
    ):
        r = await c.post("/api/v1/submissions", json={**BODY, **change})
        assert r.status_code == 422, change
    r = await c.post("/api/v1/submissions", json={**BODY, "url": "https://www.sbr.int/jobs"})
    assert r.json()["detail"] == "official or known lookalike domain"


async def test_platform_check(api: Any, make_user: Any, login: Any) -> None:
    _platforms(api)
    await make_user("alice", ("analyst",))
    c = await login("alice")
    li = (
        await c.get("/api/v1/submissions/platform", params={"url": "https://t.me/sbr_support"})
    ).json()
    assert li == {
        "url": "https://t.me/sbr_support",
        "platform": "telegram",
        "platform_name": "Telegram",
        "fetch": False,
        "error": None,
    }
    other = (
        await c.get("/api/v1/submissions/platform", params={"url": "https://sbr-pay.top/x"})
    ).json()
    assert other["platform"] is None and other["fetch"] is True
    bad = (await c.get("/api/v1/submissions/platform", params={"url": "http://10.1.1.1/"})).json()
    assert bad["url"] is None and bad["error"] == "private or reserved address"


async def test_only_triage_role_can_submit(api: Any, make_user: Any, login: Any) -> None:
    _platforms(api)
    for name, role in (("vic", "viewer"), ("rob", "responder"), ("aud", "auditor")):
        await make_user(name, (role,))
        c = await login(name)
        assert (await c.post("/api/v1/submissions", json=BODY)).status_code == 403
        assert (
            await c.get("/api/v1/submissions/platform", params={"url": BODY["url"]})
        ).status_code == 403


async def test_platform_submission_takedown_targets_platform(
    api: Any, make_user: Any, login: Any
) -> None:
    _platforms(api)
    api.app.state.deps.templates_dir = REPO / "config" / "takedown" / "templates"
    await make_user("alice", ("analyst",))
    c = await login("alice")
    alert_id = (await c.post("/api/v1/submissions", json=BODY)).json()["alert_id"]
    targets = (await c.get(f"/api/v1/alerts/{alert_id}/takedown-targets")).json()["targets"]
    assert [(t["kind"], t["id"]) for t in targets] == [("platform", "platform:linkedin")]
    r = await c.post(
        f"/api/v1/alerts/{alert_id}/takedowns",
        json={"target_id": "platform:linkedin", "language": "zh-CN"},
    )
    assert r.status_code == 201, r.text
    assert "冒充行长招聘" in r.json()["body"]


async def test_takedown_uses_reported_observed_time(api: Any, make_user: Any, login: Any) -> None:
    _platforms(api)
    api.app.state.deps.templates_dir = REPO / "config" / "takedown" / "templates"
    await make_user("alice", ("analyst",))
    c = await login("alice")
    body = {**BODY, "observed_at": "2026-09-01T08:00:00Z"}
    alert_id = (await c.post("/api/v1/submissions", json=body)).json()["alert_id"]
    r = await c.post(
        f"/api/v1/alerts/{alert_id}/takedowns",
        json={"target_id": "platform:linkedin", "language": "en-US"},
    )
    assert r.status_code == 201, r.text
    assert (
        "First seen: 2026-09-01 08:00 UTC" in r.json()["body"]
    )  # 分析员看到线索的时间早于提交时间


async def test_uploaded_screenshot_shows_in_queue(api: Any, make_user: Any, login: Any) -> None:
    _platforms(api)
    await make_user("alice", ("analyst",))
    c = await login("alice")
    alert_id = (await c.post("/api/v1/submissions", json=BODY)).json()["alert_id"]
    buf = io.BytesIO()
    Image.new("RGB", (20, 10), "red").save(buf, format="PNG")
    up = await c.post(
        f"/api/v1/alerts/{alert_id}/evidence",
        content=buf.getvalue(),
        headers={"Content-Type": "image/png"},
    )
    assert up.status_code == 201
    items = (await c.get("/api/v1/alerts")).json()["items"]
    assert [x["screenshot_id"] for x in items if x["id"] == alert_id] == [up.json()["id"]]


async def test_escalated_platform_alert_keeps_uploaded_screenshot(
    api: Any, make_user: Any, login: Any
) -> None:
    _platforms(api)
    await make_user("alice", ("analyst",))
    c = await login("alice")
    first = (await c.post("/api/v1/submissions", json={**BODY, "severity": "medium"})).json()
    buf = io.BytesIO()
    Image.new("RGB", (20, 10), "red").save(buf, format="PNG")
    up = await c.post(
        f"/api/v1/alerts/{first['alert_id']}/evidence",
        content=buf.getvalue(),
        headers={"Content-Type": "image/png"},
    )
    assert up.status_code == 201
    second = (await c.post("/api/v1/submissions", json={**BODY, "severity": "critical"})).json()
    assert second["created_alert"] and second["alert_id"] != first["alert_id"]
    # 平台链接不会自动截图：升级后的新告警沿用同一链接此前上传的截图
    items = (await c.get("/api/v1/alerts")).json()["items"]
    assert [x["screenshot_id"] for x in items if x["id"] == second["alert_id"]] == [up.json()["id"]]
