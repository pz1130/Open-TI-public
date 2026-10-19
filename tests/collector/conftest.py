from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from opti.collector.client import GatewayClient
from opti.core.config import ProjectRules
from opti.gateway.app import create_gateway
from opti.gateway.jobs import MemoryJobQueue
from opti.gateway.testing import TOKEN, make_deps
from opti.sdk.models import RawItem
from opti.sdk.registry import Registry
from opti.sdk.runtime import RuntimePaths
from opti.storage.objects import MemoryObjectStore

ECHO = {
    "id": "echo", "name": "Echo", "version": "0.1.0", "category": "ct", "kind": ["poll"],
    "tier": "free", "entrypoint": "opti.sdk.testing:EchoConnector",
    "config_schema": {"type": "object", "properties": {"items": {"type": "array", "default": []},
                                                       "delay": {"type": "number", "default": 0}}},
}  # fmt: skip
STATIC = {
    "id": "static", "name": "Static", "version": "0.1.0", "category": "enrichment",
    "kind": ["enricher"], "tier": "free", "entrypoint": "opti.sdk.testing:StaticEnricher",
    "config_schema": {"type": "object", "properties": {"data": {"type": "object"}}},
}  # fmt: skip
PNG_B64 = "iVBORw0KGgo="  # PNG 文件头


@dataclass
class World:
    registry: Registry
    paths: RuntimePaths
    jobs: MemoryJobQueue
    store: MemoryObjectStore
    enqueued: list[RawItem]
    client: GatewayClient


def write_registry(root: Path, cfg: Path, *, static_egress: str = "overseas") -> None:
    for m in (ECHO, {**STATIC, "egress": static_egress}):
        (root / str(m["id"])).mkdir(parents=True, exist_ok=True)
        (root / str(m["id"]) / "connector.yaml").write_text(yaml.safe_dump(m))
    cfg.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = [{"matches": [{"domain": "sbr-loans.com"}]},
                                   {"matches": [{"domain": "sbr-grant.top"}]}]  # fmt: skip
    (cfg / "echo.yaml").write_text(
        yaml.safe_dump({"enabled": True, "license_approved": True, "config": {"items": items}})
    )
    data = {
        "exists": True,
        "artifacts": [{"name": "screenshot", "content_type": "image/png", "data_b64": PNG_B64}],
    }
    (cfg / "static.yaml").write_text(
        yaml.safe_dump({"enabled": True, "license_approved": True, "config": {"data": data}})
    )


@pytest.fixture
async def world(tmp_path: Path, sbr_rules: ProjectRules) -> AsyncIterator[World]:
    root, cfg = tmp_path / "connectors", tmp_path / "config"
    write_registry(root, cfg)
    registry = Registry([root])
    jobs, store = MemoryJobQueue(), MemoryObjectStore()
    deps, enqueued = make_deps(sbr_rules, registry=registry, jobs=jobs, store=store)
    deps.config_dir = cfg
    client = GatewayClient(
        "http://gw",
        TOKEN,
        transport=httpx.ASGITransport(app=create_gateway(deps), raise_app_exceptions=False),
    )
    yield World(
        registry,
        RuntimePaths(config_dir=cfg, state_dir=tmp_path / "data"),
        jobs,
        store,
        enqueued,
        client,
    )
    await client.aclose()


@pytest.fixture
def registry_writer() -> Callable[..., None]:
    return write_registry
