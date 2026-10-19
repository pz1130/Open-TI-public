"""API 启动时应优先使用数据库中已保存的配置。"""

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from opti.api.server import serve_api
from opti.configs import revisions
from opti.db.engine import make_engine, make_sessionmaker
from opti.pipeline.broker import broker
from opti.settings import Settings

pytestmark = pytest.mark.db


async def test_saved_config_starts_api_when_bootstrap_files_are_invalid(
    clean_db: str, sbr_rules_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(clean_db)
    sessions = make_sessionmaker(engine)
    async with sessions.begin() as session:
        await revisions.append(
            session, "rules", sbr_rules_path.read_text(encoding="utf-8"),
            base_version=0, user="test", note=None, now=datetime.now(UTC),
        )  # fmt: skip
        await revisions.append(
            session, "organization", "name: Database Org\n",
            base_version=0, user="test", note=None, now=datetime.now(UTC),
        )  # fmt: skip
    await engine.dispose()

    bad_rules = tmp_path / "bad-rules.yaml"
    bad_org = tmp_path / "bad-org.yaml"
    bad_rules.write_text("project: [\n", encoding="utf-8")
    bad_org.write_text("name: [\n", encoding="utf-8")
    settings = Settings(
        database_url=clean_db,
        rules_path=bad_rules,
        organization_path=bad_org,
        state_dir=tmp_path / "state",
    )
    started: list[tuple[int, int, str]] = []

    async def no_broker() -> None:
        return None

    async def inspect_app(server: uvicorn.Server) -> None:
        deps: Any = server.config.app.state.deps
        snap = deps.config.snapshot
        started.append((snap.rules_version, snap.organization_version, deps.organization.name))

    monkeypatch.setattr(broker, "startup", no_broker)
    monkeypatch.setattr(broker, "shutdown", no_broker)
    monkeypatch.setattr(uvicorn.Server, "serve", inspect_app)
    await asyncio.to_thread(serve_api, settings)

    assert started == [(1, 1, "Database Org")]
