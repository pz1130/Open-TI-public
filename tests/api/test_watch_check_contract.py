"""Queue acknowledgement contract without a database, broker or running API server."""

from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from opti.api.app import create_api
from opti.api.deps import ApiDeps, Principal, current_user
from opti.api.rbac import Perm
from opti.api.routes import watchlist
from opti.configs.runtime import ConfigRuntime
from opti.core.config import ProjectRules
from opti.settings import Settings


@pytest.fixture
async def watch_client(sbr_rules: ProjectRules, monkeypatch: Any) -> Any:
    entry = SimpleNamespace(
        id=4,
        project_id=sbr_rules.project,
        domain="example.test",
        expires_at=None,
        paused_by_suppression=False,
        last_checked_at=None,
    )
    session = MagicMock()
    session.get = AsyncMock(return_value=entry)
    sessions = MagicMock()
    sessions.begin.return_value.__aenter__ = AsyncMock(return_value=session)
    sessions.begin.return_value.__aexit__ = AsyncMock(return_value=False)
    queued, audit = AsyncMock(), AsyncMock()
    monkeypatch.setattr(watchlist.recheck_watched_domain, "kiq", queued)
    monkeypatch.setattr(watchlist, "record", audit)
    app = create_api(
        ApiDeps(
            settings=Settings(broker_url="redis://unused:6379/0"),
            config=ConfigRuntime.static(sbr_rules),
            sessions=sessions,
            store=None,
        )
    )
    principal = Principal(1, "analyst", "", ("analyst",), frozenset({Perm.WATCHLIST_WRITE}))
    app.dependency_overrides[current_user] = lambda: principal
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://test",
        headers={"X-Requested-With": "opti"},
    ) as client:
        yield SimpleNamespace(
            client=client,
            app=app,
            entry=entry,
            queued=queued,
            audit=audit,
            principal=principal,
        )


async def test_acknowledges_only_after_queue_accepts(watch_client: Any) -> None:
    response = await watch_client.client.post("/api/v1/watchlist/4/check")
    assert response.status_code == 202
    assert response.json() == {
        "status": "queued",
        "watch_id": 4,
        "request_id": response.headers["X-Request-ID"],
    }
    watch_client.queued.assert_awaited_once_with(4, None)
    watch_client.audit.assert_awaited_once()
    request = watch_client.audit.call_args.args[1]
    assert request.state.request_id == response.json()["request_id"]


async def test_queue_failure_is_not_acknowledged(watch_client: Any) -> None:
    watch_client.queued.side_effect = ConnectionError("broker unavailable")
    response = await watch_client.client.post("/api/v1/watchlist/4/check")
    assert response.status_code == 503
    assert response.json() == {"detail": "failed to queue watch check"}


@pytest.mark.parametrize("inactive", ["project", "suppressed"])
async def test_other_project_or_inactive_watch_cannot_queue(
    watch_client: Any, inactive: str
) -> None:
    if inactive == "project":
        watch_client.entry.project_id = "other-project"
    else:
        watch_client.entry.paused_by_suppression = True
    response = await watch_client.client.post("/api/v1/watchlist/4/check")
    assert response.status_code == (404 if inactive == "project" else 409)
    watch_client.queued.assert_not_awaited()


async def test_read_only_user_cannot_queue(watch_client: Any) -> None:
    watch_client.app.dependency_overrides[current_user] = lambda: replace(
        watch_client.principal, perms=frozenset({Perm.WATCHLIST_READ})
    )
    response = await watch_client.client.post("/api/v1/watchlist/4/check")
    assert response.status_code == 403
    watch_client.queued.assert_not_awaited()


async def test_forced_password_user_cannot_bypass_ui_to_queue(
    watch_client: Any, monkeypatch: Any
) -> None:
    from opti.api import deps

    watch_client.app.dependency_overrides.pop(current_user)
    monkeypatch.setattr(
        deps, "resolve_session", AsyncMock(return_value=SimpleNamespace(must_change_password=True))
    )
    watch_client.client.cookies.set("opti_session", "test-only-session")
    response = await watch_client.client.post("/api/v1/watchlist/4/check")
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "password_change_required"
    watch_client.queued.assert_not_awaited()
