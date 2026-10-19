from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from opti.db.models import AuditLog
from opti.service_control import ControllerState, ServiceState, atomic_json, operation

pytestmark = pytest.mark.db


def connected(api: Any, directory: Path) -> None:
    api.deps.settings = replace(api.deps.settings, service_control_dir=directory)
    atomic_json(
        directory / "controller.json",
        ControllerState(
            updated_at=datetime.now(UTC),
            services=[
                ServiceState(name="api", containers=1, running=1),
                ServiceState(name="worker", containers=1, running=1),
            ],
        ),
    )


async def test_restart_requires_admin_and_connected_controller(
    api: Any, make_user: Any, login: Any, tmp_path: Path
) -> None:
    await make_user("analyst")
    analyst = await login("analyst")
    assert (await analyst.get("/api/v1/admin/services")).status_code == 403
    assert (
        await analyst.post("/api/v1/admin/services/restart", json={"services": ["api"]})
    ).status_code == 403
    await make_user("admin", ("platform_admin",))
    admin = await login("admin")
    assert (await admin.get("/api/v1/admin/services")).json()["problem"] == "not_configured"
    assert (
        await admin.post("/api/v1/admin/services/restart", json={"services": ["api"]})
    ).status_code == 503
    connected(api, tmp_path)
    for body in (
        {"services": ["postgres"]},
        {"services": []},
        {"services": ["api"], "command": "anything"},
    ):
        assert (await admin.post("/api/v1/admin/services/restart", json=body)).status_code == 422
    response = await admin.post(
        "/api/v1/admin/services/restart",
        json={"services": ["api", "worker"], "reason": "管理员维护"},
    )
    assert response.status_code == 202, response.text
    assert response.json()["phase"] == "queued"
    assert response.headers["Cache-Control"] == "no-store"
    assert operation(tmp_path).id == response.json()["id"]
    assert (
        await admin.post("/api/v1/admin/services/restart", json={"services": ["api"]})
    ).status_code == 409
    current = await admin.get("/api/v1/admin/services")
    assert current.json()["operation"]["id"] == response.json()["id"]
    async with api.sessions() as session:
        logs = (
            await session.scalars(
                select(AuditLog).where(AuditLog.action == "system.services_restart_requested")
            )
        ).all()
    assert len(logs) == 1 and logs[0].actor == "admin"
    assert logs[0].detail["services"] == ["api", "worker"]


async def test_audit_failure_never_enqueues_restart(
    api: Any, make_user: Any, login: Any, tmp_path: Path, monkeypatch
) -> None:
    from opti.api.routes import system

    connected(api, tmp_path)
    await make_user("admin", ("platform_admin",))
    admin = await login("admin")

    async def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(system, "record", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await admin.post("/api/v1/admin/services/restart", json={"services": ["api"]})
    assert operation(tmp_path) is None
