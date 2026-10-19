"""Isolated Docker restart controller; the API only shares a file queue with it.

No HTTP listener, shell execution or arbitrary container IDs from requests. Only
api/worker containers belonging to the configured Compose project can restart.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

Service = Literal["api", "worker"]
SERVICES: tuple[Service, ...] = ("api", "worker")
ACTIVE = {"queued", "running"}


class ControlError(Exception):
    pass


class ControlBusy(ControlError):
    pass


class RestartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    services: list[Service] = Field(min_length=1, max_length=2)
    reason: str = Field(default="", max_length=300)


class RestartOperation(BaseModel):
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    services: list[Service] = Field(min_length=1, max_length=2)
    phase: Literal["queued", "running", "completed", "failed"]
    requested_at: datetime
    updated_at: datetime
    completed_services: list[Service] = Field(default_factory=list)
    error: str | None = None


class ServiceState(BaseModel):
    name: Service
    containers: int
    running: int


class ControllerState(BaseModel):
    updated_at: datetime
    services: list[ServiceState]
    error: str | None = None


class ServiceStatus(BaseModel):
    available: bool
    services: list[ServiceState] = Field(default_factory=list)
    operation: RestartOperation | None = None
    problem: Literal["not_configured", "offline", "docker_unavailable"] | None = None


def atomic_json(path: Path, value: BaseModel) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".control-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(value.model_dump_json())
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)  # State contains no credentials; readable by the API uid.
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def operation(directory: Path) -> RestartOperation | None:
    try:
        return RestartOperation.model_validate_json((directory / "operation.json").read_bytes())
    except FileNotFoundError:
        return None


@contextmanager
def queue_lock(directory: Path) -> Iterator[None]:
    # Nonblocking: never block the API event loop while another request awaits its audit commit.
    fd = os.open(directory / "queue.lock", os.O_CREAT | os.O_RDONLY, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ControlBusy("another operation is being submitted") from None
        yield
    finally:
        os.close(fd)


def status(directory: Path | None, *, now: datetime | None = None) -> ServiceStatus:
    if directory is None:
        return ServiceStatus(available=False, problem="not_configured")
    try:
        current = operation(directory)
        controller = ControllerState.model_validate_json(
            (directory / "controller.json").read_bytes()
        )
        age = (now or datetime.now(UTC)) - controller.updated_at
        if not timedelta(seconds=-5) <= age <= timedelta(seconds=15):
            return ServiceStatus(available=False, operation=current, problem="offline")
        return ServiceStatus(
            available=controller.error is None,
            services=controller.services,
            operation=current,
            problem="docker_unavailable" if controller.error else None,
        )
    except (OSError, ValueError):
        return ServiceStatus(available=False, problem="offline")


class DockerController:
    def __init__(self, project: str, http: httpx.AsyncClient) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise ValueError("invalid Compose project")
        self.project, self.http = project, http

    def owned(self, labels: dict[str, str], service: Service) -> bool:
        return (
            labels.get("com.docker.compose.project") == self.project
            and labels.get("com.docker.compose.service") == service
            and labels.get("com.docker.compose.oneoff", "false").lower() == "false"
        )

    async def containers(self, service: Service) -> list[dict[str, Any]]:
        filters = {
            "label": [
                f"com.docker.compose.project={self.project}",
                f"com.docker.compose.service={service}",
            ]
        }
        response = await self.http.get(
            "/containers/json", params={"all": "true", "filters": json.dumps(filters)}
        )
        response.raise_for_status()
        return [r for r in response.json() if self.owned(r.get("Labels") or {}, service)]

    async def inventory(self) -> list[ServiceState]:
        items = []
        for service in SERVICES:
            rows = await self.containers(service)
            items.append(
                ServiceState(
                    name=service,
                    containers=len(rows),
                    running=sum(r.get("State") == "running" for r in rows),
                )
            )
        return items

    async def restart(self, service: Service) -> None:
        rows = await self.containers(service)
        if not rows:
            raise ControlError("service_not_found")
        for row in rows:
            identity = row.get("Id", "")
            if not re.fullmatch(r"[a-f0-9]{64}", identity):
                raise ControlError("invalid_container")
            # Recheck labels immediately before the only mutating Docker endpoint.
            response = await self.http.get(f"/containers/{identity}/json")
            response.raise_for_status()
            if not self.owned(response.json().get("Config", {}).get("Labels") or {}, service):
                raise ControlError("container_scope_changed")
            grace = 600 if service == "worker" else 30
            response = await self.http.post(
                f"/containers/{identity}/restart", params={"t": grace}, timeout=grace + 30
            )
            response.raise_for_status()
            response = await self.http.get(f"/containers/{identity}/json")
            response.raise_for_status()
            if not response.json().get("State", {}).get("Running"):
                raise ControlError("service_not_running")

    async def execute(self, directory: Path, job: RestartOperation) -> None:
        try:
            # Worker first: the API can still report progress while it drains.
            for service in SERVICES[::-1]:
                if service not in job.services:
                    continue
                await self.restart(service)
                job.completed_services.append(service)
                job.updated_at = datetime.now(UTC)
                atomic_json(directory / "operation.json", job)
            job.phase = "completed"
        except (httpx.HTTPError, ControlError, OSError) as error:
            job.phase = "failed"
            job.error = str(error) if isinstance(error, ControlError) else "restart_failed"
        finally:
            job.updated_at = datetime.now(UTC)
            atomic_json(directory / "operation.json", job)

    async def run(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        # One controller owns this queue even if accidentally launched twice.
        guard = os.open(directory / "controller.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        task: asyncio.Task[None] | None = None
        try:
            with queue_lock(directory):
                old = operation(directory)
                if old and old.phase == "running":
                    old.phase, old.error, old.updated_at = (
                        "failed",
                        "controller_restarted",
                        datetime.now(UTC),
                    )
                    atomic_json(directory / "operation.json", old)
            while True:
                try:
                    inventory = await self.inventory()
                    heartbeat = ControllerState(updated_at=datetime.now(UTC), services=inventory)
                except (httpx.HTTPError, ValueError):
                    heartbeat = ControllerState(
                        updated_at=datetime.now(UTC), services=[], error="docker_unavailable"
                    )
                atomic_json(directory / "controller.json", heartbeat)
                if task is not None and task.done():
                    task.result()
                    task = None
                if task is None and heartbeat.error is None:
                    try:
                        with queue_lock(directory):
                            job = operation(directory)
                            if (
                                job
                                and job.phase == "queued"
                                and datetime.now(UTC) >= job.requested_at + timedelta(seconds=2)
                            ):
                                job.phase, job.updated_at = "running", datetime.now(UTC)
                                atomic_json(directory / "operation.json", job)
                                task = asyncio.create_task(self.execute(directory, job))
                    except ControlBusy:
                        pass
                await asyncio.sleep(2)
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            os.close(guard)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Allowlisted Compose service restart controller")
    parser.add_argument("--project", default="opti")
    parser.add_argument("--directory", type=Path, default=Path("/run/opti-control"))
    parser.add_argument("--socket", default="/var/run/docker.sock")
    args = parser.parse_args()
    async with httpx.AsyncClient(
        base_url="http://docker",
        transport=httpx.AsyncHTTPTransport(uds=args.socket),
        timeout=10,
        trust_env=False,
    ) as client:
        await DockerController(args.project, client).run(args.directory)


if __name__ == "__main__":
    asyncio.run(main())
