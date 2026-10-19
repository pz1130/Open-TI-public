"""Only disposable containers with a unique test project label are restarted."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from testcontainers.core.container import DockerContainer

from opti.service_control import DockerController, RestartOperation, operation

pytestmark = pytest.mark.db


async def test_real_docker_restart_is_limited_to_test_project(tmp_path: Path) -> None:
    socket = Path("/var/run/docker.sock")
    if not socket.exists():
        socket = Path.home() / ".docker/run/docker.sock"
    if not socket.exists():
        pytest.skip("Docker Unix socket not available")
    project = "opti-restart-test-" + uuid.uuid4().hex[:12]
    labels = {
        "com.docker.compose.project": project,
        "com.docker.compose.service": "api",
        "com.docker.compose.oneoff": "False",
    }
    with (
        DockerContainer("alpine:3.20")
        .with_kwargs(labels=labels, network_mode="none")
        .with_command("sleep 300") as container
    ):
        docker_container = container.get_wrapped_container()
        docker_container.reload()
        before = docker_container.attrs["State"]["StartedAt"]
        async with httpx.AsyncClient(
            base_url="http://docker",
            transport=httpx.AsyncHTTPTransport(uds=str(socket)),
            timeout=10,
            trust_env=False,
        ) as http:
            controller = DockerController(project, http)
            inventory = await controller.inventory()
            assert [(s.name, s.containers) for s in inventory] == [("api", 1), ("worker", 0)]
            now = datetime.now(UTC)
            job = RestartOperation(
                id=uuid.uuid4().hex,
                services=["api"],
                phase="running",
                requested_at=now,
                updated_at=now,
            )
            await controller.execute(tmp_path, job)
        docker_container.reload()
        assert operation(tmp_path).phase == "completed"
        assert docker_container.attrs["State"]["Running"]
        assert docker_container.attrs["State"]["StartedAt"] != before
