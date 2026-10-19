import pytest

from opti.pipeline import tasks
from tests.api.conftest import ApiWorld

pytestmark = pytest.mark.db


async def _admin(make_user, login):  # type: ignore[no-untyped-def]
    await make_user("ops", ("platform_admin",))
    return await login("ops")


async def test_retention_shortening_needs_confirmation(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(make_user, login)
    longer = await c.put(
        "/api/v1/config/retention", json={"data": {"cases_days": 2000}, "base_version": 0}
    )
    assert longer.status_code == 200, longer.text
    assert longer.json()["version"] == 1

    shorter = await c.put(
        "/api/v1/config/retention", json={"data": {"cases_days": 600}, "base_version": 1}
    )
    assert shorter.status_code == 409, shorter.text
    detail = shorter.json()["detail"]
    assert detail["reason"] == "retention_shortened"
    assert detail["preview_error"] is None
    assert detail["preview_capped"] is False
    assert set(detail["preview"]) >= {"findings", "cases", "raw_item_partitions"}

    saved = await c.put(
        "/api/v1/config/retention",
        json={"data": {"cases_days": 600}, "base_version": 1, "confirm_retention": True},
    )
    assert saved.status_code == 200, saved.text
    assert api.deps.config.snapshot.retention.cases_days == 600

    restored = await c.post(
        "/api/v1/config/retention/revisions/1/restore", json={"base_version": 2}
    )
    assert restored.status_code == 200, restored.text
    blocked = await c.post("/api/v1/config/retention/revisions/2/restore", json={"base_version": 3})
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["reason"] == "retention_shortened"


async def test_campaigns_save_triggers_recompute(
    api: ApiWorld, make_user, login, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    queued: list[str] = []

    async def kiq() -> None:
        queued.append("recompute")

    monkeypatch.setattr(tasks.recompute_campaigns, "kiq", kiq)
    c = await _admin(make_user, login)
    r = await c.put("/api/v1/config/campaigns", json={"data": {"max_share": 20}, "base_version": 0})
    assert r.status_code == 200, r.text
    assert queued == ["recompute"]
    same = await c.put(
        "/api/v1/config/campaigns", json={"data": {"max_share": 20}, "base_version": 1}
    )
    assert same.status_code == 200, same.text
    assert queued == ["recompute"]


async def test_phase3_permissions(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    await make_user("vic", ("viewer",))
    viewer = await login("vic")
    assert (await viewer.get("/api/v1/config/retention")).status_code == 200
    assert (
        await viewer.put("/api/v1/config/retention", json={"data": {}, "base_version": 0})
    ).status_code == 403
    admin = await _admin(make_user, login)
    assert (await admin.get("/api/v1/config/retention/secrets")).status_code == 404
    assert (await admin.get("/api/v1/config/alerting/secrets")).status_code == 200
