from pathlib import Path

import pytest
import yaml

from opti.core.config import ProjectRules
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry
from opti.sdk.runtime import ConnectorBlocked, RuntimePaths, collect, create
from opti.sdk.testing import EchoConnector

ECHO = {
    "id": "echo",
    "name": "Echo",
    "version": "0.1.0",
    "category": "ct",
    "kind": ["poll"],
    "tier": "free",
    "entrypoint": "opti.sdk.testing:EchoConnector",
    "config_schema": {
        "type": "object",
        "properties": {
            "items": {"type": "array", "default": []},
            "delay": {"type": "number", "default": 0},
        },
    },
}


def _setup(tmp_path: Path, instance: dict[str, object]) -> tuple[Registry, RuntimePaths]:
    root = tmp_path / "connectors"
    (root / "echo").mkdir(parents=True)
    (root / "echo" / "connector.yaml").write_text(yaml.safe_dump(ECHO))
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "echo.yaml").write_text(yaml.safe_dump(instance))
    return Registry([root]), RuntimePaths(config_dir=cfg, state_dir=tmp_path / "data")


def test_create_blocked(tmp_path: Path, sbr_rules: ProjectRules) -> None:
    reg, paths = _setup(tmp_path, {"enabled": True})
    with pytest.raises(ConnectorBlocked, match="license_not_approved"):
        create(reg, "echo", sbr_rules, paths=paths)
    assert isinstance(
        create(reg, "echo", sbr_rules, paths=paths, allow_unapproved=True), EchoConnector
    )


async def test_collect_respects_max_items(tmp_path: Path, sbr_rules: ProjectRules) -> None:
    reg, paths = _setup(
        tmp_path,
        {
            "enabled": True,
            "license_approved": True,
            "config": {"items": [{"n": 1}, {"n": 2}, {"n": 3}]},
        },
    )
    conn = create(reg, "echo", sbr_rules, paths=paths)
    assert isinstance(conn, EchoConnector)
    items = [i async for i in collect(conn, build_query_plan(sbr_rules), max_items=2)]
    assert [i.payload["n"] for i in items] == [1, 2]


async def test_collect_respects_deadline(tmp_path: Path, sbr_rules: ProjectRules) -> None:
    reg, paths = _setup(
        tmp_path,
        {"enabled": True, "license_approved": True, "config": {"items": [{"n": 1}], "delay": 5}},
    )
    conn = create(reg, "echo", sbr_rules, paths=paths)
    assert isinstance(conn, EchoConnector)
    assert [i async for i in collect(conn, build_query_plan(sbr_rules), seconds=0.05)] == []
