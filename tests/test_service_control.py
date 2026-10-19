import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from opti.service_control import (
    ControlBusy,
    ControlError,
    ControllerState,
    DockerController,
    RestartOperation,
    RestartRequest,
    ServiceState,
    atomic_json,
    operation,
    queue_lock,
    status,
)

NOW = datetime.now(UTC)
LABELS = {
    "com.docker.compose.project": "opti",
    "com.docker.compose.service": "api",
    "com.docker.compose.oneoff": "False",
}


def test_status_bounds_and_nonblocking_lock(tmp_path: Path) -> None:
    assert status(None).problem == "not_configured"
    assert status(tmp_path).problem == "offline"
    atomic_json(
        tmp_path / "controller.json",
        ControllerState(
            updated_at=NOW, services=[ServiceState(name="api", containers=1, running=1)]
        ),
    )
    assert status(tmp_path, now=NOW).available
    assert not status(tmp_path, now=NOW + timedelta(seconds=16)).available
    assert not status(tmp_path, now=NOW - timedelta(seconds=6)).available
    assert (tmp_path / "controller.json").stat().st_mode & 0o777 == 0o644
    with queue_lock(tmp_path), pytest.raises(ControlBusy), queue_lock(tmp_path):
        pass
    with queue_lock(tmp_path):
        pass
    atomic_json(
        tmp_path / "controller.json",
        ControllerState(updated_at=NOW, services=[], error="docker_unavailable"),
    )
    assert status(tmp_path, now=NOW).problem == "docker_unavailable"


@pytest.mark.parametrize(
    "value", [{"services": ["postgres"]}, {"services": []}, {"services": ["api"], "command": "rm"}]
)
def test_requests_allow_only_fixed_services(value: dict) -> None:
    with pytest.raises(ValidationError):
        RestartRequest.model_validate(value)


async def test_restart_revalidates_scope_and_only_posts_fixed_endpoint(tmp_path: Path) -> None:
    seen = []
    identity = "a" * 64

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.url.params)))
        if request.url.path == "/containers/json":
            return httpx.Response(
                200,
                json=[
                    {"Id": identity, "Labels": LABELS},
                    {"Id": "b" * 64, "Labels": {**LABELS, "com.docker.compose.project": "other"}},
                    {"Id": "c" * 64, "Labels": {**LABELS, "com.docker.compose.oneoff": "True"}},
                ],
            )
        if request.method == "POST":
            return httpx.Response(204)
        return httpx.Response(200, json={"Config": {"Labels": LABELS}, "State": {"Running": True}})

    async with httpx.AsyncClient(
        base_url="http://docker", transport=httpx.MockTransport(respond)
    ) as http:
        controller = DockerController("opti", http)
        job = RestartOperation(
            id="d" * 32, services=["api"], phase="running", requested_at=NOW, updated_at=NOW
        )
        await controller.execute(tmp_path, job)
    assert [(m, p, qs) for m, p, qs in seen if m == "POST"] == [
        ("POST", f"/containers/{identity}/restart", {"t": "30"})
    ]
    assert operation(tmp_path).phase == "completed"
    assert operation(tmp_path).completed_services == ["api"]


async def test_changed_container_scope_does_not_restart() -> None:
    identity = "a" * 64

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        body = (
            [{"Id": identity, "Labels": LABELS}]
            if request.url.path == "/containers/json"
            else {"Config": {"Labels": {**LABELS, "com.docker.compose.project": "foreign"}}}
        )
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(
        base_url="http://docker", transport=httpx.MockTransport(respond)
    ) as http:
        with pytest.raises(ControlError, match="scope_changed"):
            await DockerController("opti", http).restart("api")


async def test_worker_first_and_partial_failure_is_not_repeated(
    tmp_path: Path, monkeypatch
) -> None:
    calls = []
    async with httpx.AsyncClient() as http:
        controller = DockerController("opti", http)

        async def restart(service):
            calls.append(service)
            if service == "api":
                raise httpx.ConnectError("sensitive daemon details")

        monkeypatch.setattr(controller, "restart", restart)
        job = RestartOperation(
            id="a" * 32,
            services=["api", "worker"],
            phase="running",
            requested_at=NOW,
            updated_at=NOW,
        )
        await controller.execute(tmp_path, job)
    result = operation(tmp_path)
    assert calls == ["worker", "api"]
    assert result.phase == "failed" and result.completed_services == ["worker"]
    assert result.error == "restart_failed"
    assert "sensitive" not in (tmp_path / "operation.json").read_text()


async def test_controller_recovery_marks_interrupted_operation_failed(
    tmp_path: Path, monkeypatch
) -> None:
    atomic_json(
        tmp_path / "operation.json",
        RestartOperation(
            id="a" * 32, services=["api"], phase="running", requested_at=NOW, updated_at=NOW
        ),
    )

    class Finished(Exception):
        pass

    async def stop(_):
        raise Finished

    monkeypatch.setattr(asyncio, "sleep", stop)

    def respond(request):
        assert request.method == "GET"
        return httpx.Response(200, json=[])

    async with httpx.AsyncClient(
        base_url="http://docker", transport=httpx.MockTransport(respond)
    ) as http:
        with pytest.raises(Finished):
            await DockerController("opti", http).run(tmp_path)
    assert operation(tmp_path).phase == "failed"
    assert operation(tmp_path).error == "controller_restarted"
