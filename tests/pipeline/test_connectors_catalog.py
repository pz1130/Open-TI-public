import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import CollectorNode, ConnectorRun
from opti.pipeline import connectors
from opti.sdk.context import EnvSecretProvider
from opti.sdk.registry import Registry

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, tzinfo=UTC)


def _manifest(cid: str, *, kind: tuple[str, ...] = ("poll",), egress: str = "overseas",
              creds: tuple[str, ...] = ()) -> dict[str, Any]:  # fmt: skip
    enricher = "enricher" in kind
    return {
        "id": cid, "name": cid.title(), "version": "0.1.0", "category": "enrichment" if enricher else "ct",
        "kind": list(kind), "tier": "free", "egress": egress, "commercial_use": "restricted",
        "entrypoint": "opti.sdk.testing:StaticEnricher" if enricher else "opti.sdk.testing:EchoConnector",
        "tos_url": "https://tos.example/terms", "schedule": {"default": "*/30 * * * *"},
        "credentials": [{"name": c, "required": True} for c in creds],
    }  # fmt: skip


def _world(tmp_path: Path) -> tuple[Registry, Path]:
    root, cfg = tmp_path / "connectors", tmp_path / "config"
    cfg.mkdir()
    specs = [
        _manifest("alpha", creds=("api_key",)), _manifest("beta", egress="domestic"),
        _manifest("gamma", kind=("stream",)), _manifest("delta", kind=("enricher",)), _manifest("epsilon"),
    ]  # fmt: skip
    for spec in specs:
        (root / spec["id"]).mkdir(parents=True)
        (root / spec["id"] / "connector.yaml").write_text(yaml.safe_dump(spec), encoding="utf-8")
    for cid in ("alpha", "beta", "gamma"):
        (cfg / f"{cid}.yaml").write_text(
            yaml.safe_dump({"enabled": True, "license_approved": True, "license_ref": "LEGAL-1"}),
            encoding="utf-8",
        )
    return Registry([root]), cfg


def _run(cid: str, ago: timedelta, status: str, items: int = 0, message: str = "") -> ConnectorRun:
    return ConnectorRun(connector_id=cid, started_at=NOW - ago, ended_at=NOW - ago + timedelta(minutes=1),
                        status=status, items=items, errors=int(status == "error"), message=message)  # fmt: skip


async def test_catalog_local(session: AsyncSession, tmp_path: Path) -> None:
    registry, cfg = _world(tmp_path)
    session.add_all([
        _run("alpha", timedelta(days=3), "ok", items=5, message="token=super-secret-value"),
        _run("beta", timedelta(hours=2), "ok", items=1), _run("beta", timedelta(hours=1), "error", message="HttpError: 503"),
    ])  # fmt: skip
    await session.flush()
    secrets = EnvSecretProvider({"OPTI_SECRET_ALPHA_API_KEY": "super-secret-value"})
    rows = {
        r["id"]: r
        for r in await connectors.catalog(session, registry, cfg, secrets, remote=False, now=NOW)
    }
    a = rows["alpha"]
    assert (
        a["runnable"] is True and a["health"] == "stale" and a["location"] == "platform"
    )  # 最近一次成功在 3 天前
    assert a["credentials"] == [{"name": "api_key", "required": True, "configured": True}]
    assert a["license_approved"] and a["license_ref"] == "LEGAL-1" and a["last_run"]["items"] == 5
    assert a["last_run"]["message"] == ""
    assert a["tos_url"] == "https://tos.example/terms" and a["schedule"] == "*/30 * * * *"
    b = rows["beta"]
    assert b["health"] == "failing" and b["runs_24h"] == 2 and b["errors_24h"] == 1
    assert b["last_run"]["message"] == "HttpError: 503" and b["last_success_at"] is not None
    assert rows["gamma"]["health"] == "never" and rows["delta"]["health"] == "n/a"
    assert rows["epsilon"]["health"] == "disabled" and rows["epsilon"]["reason"].startswith(
        "disabled"
    )
    assert "super-secret-value" not in json.dumps(list(rows.values()), default=str)


async def test_catalog_remote_and_secrets(session: AsyncSession, tmp_path: Path) -> None:
    registry, cfg = _world(tmp_path)
    empty = EnvSecretProvider({})  # 平台上没有境外连接器的密钥
    rows = {
        r["id"]: r
        for r in await connectors.catalog(session, registry, cfg, empty, remote=True, now=NOW)
    }
    a = rows["alpha"]
    assert (
        a["health"] == "unknown"
        and a["runnable"] is None
        and a["reason"].startswith("waiting_for_node")
    )
    assert a["credentials"] == [
        {"name": "api_key", "required": True, "configured": None}
    ]  # 不能误显示为未设置
    assert rows["beta"]["location"] == "platform" and rows["beta"]["runnable"] is True
    session.add(CollectorNode(node_id="hk1", version="0.1.0", last_seen=NOW - timedelta(minutes=1), status={
        "streams": {"gamma": "running"},
        "connectors": {
            "alpha": {"runnable": False, "reason": "unconfigured：token=super-secret-value", "credentials": {"api_key": False}},
            "gamma": {"runnable": True, "reason": "ok", "credentials": {}},
        },
    }))  # fmt: skip
    await session.flush()
    rows = {
        r["id"]: r
        for r in await connectors.catalog(session, registry, cfg, empty, remote=True, now=NOW)
    }
    a = rows["alpha"]
    assert a["runnable"] is False and a["health"] == "blocked" and a["location"] == "node:hk1"
    assert a["credentials"][0]["configured"] is False
    assert "super-secret-value" not in json.dumps(a, default=str)
    assert rows["gamma"]["health"] == "ok"  # 流式连接器按节点上报的流状态


async def test_invalid_config_does_not_echo_input(session: AsyncSession, tmp_path: Path) -> None:
    registry, cfg = _world(tmp_path)
    (cfg / "alpha.yaml").write_text("enabled: super-secret-value\n", encoding="utf-8")
    rows = {
        r["id"]: r
        for r in await connectors.catalog(
            session, registry, cfg, EnvSecretProvider({}), remote=False, now=NOW
        )
    }
    assert rows["alpha"]["reason"].startswith("config_invalid")
    assert "super-secret-value" not in json.dumps(rows["alpha"], default=str)


def test_health_rules() -> None:
    h = connectors.health
    assert (
        h(("poll",), runnable=True, last_status="running", last_ok=None, stream=None, now=NOW)
        == "ok"
    )
    assert (
        h(
            ("poll",),
            runnable=True,
            last_status="ok",
            last_ok=NOW - timedelta(hours=47),
            stream=None,
            now=NOW,
        )
        == "ok"
    )
    assert (
        h(
            ("stream",),
            runnable=True,
            last_status=None,
            last_ok=None,
            stream="error: OSError",
            now=NOW,
        )
        == "failing"
    )
