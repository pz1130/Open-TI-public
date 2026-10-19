from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti import organization as org_mod
from opti.configs import kinds, revisions
from opti.configs.runtime import ConfigRuntime, ConfigSnapshot
from opti.core.config import ProjectRules
from opti.db.engine import make_sessionmaker
from opti.pipeline.campaigns import CampaignConfig
from opti.pipeline.retention import RetentionConfig
from opti.settings import Settings

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def test_registry_covers_first_phase3_batch() -> None:
    assert {"rules", "organization", "alerting", "retention", "campaigns"} <= set(kinds.KINDS)
    assert kinds.default("retention") == RetentionConfig()
    assert kinds.default("campaigns") == CampaignConfig()
    text = kinds.from_data("retention", {"raw_items_days": 30})
    assert kinds.parse("retention", text).raw_items_days == 30
    with pytest.raises(kinds.ConfigInvalid) as error:
        kinds.from_data("retention", {"cases_days": 5})
    assert error.value.errors[0]["path"] == "cases_days"
    with pytest.raises(kinds.ConfigInvalid, match="KB"):
        kinds.parse("campaigns", "x: " + "a" * 5000)


def test_new_kinds_read_files_or_defaults(tmp_path: Path) -> None:
    retention = tmp_path / "retention.yaml"
    retention.write_text("raw_items_days: 45\n", encoding="utf-8")
    settings = Settings(retention_config=retention, campaigns_config=tmp_path / "missing.yaml")
    assert kinds.parse("retention", kinds.read_file("retention", settings)).raw_items_days == 45
    assert kinds.parse("campaigns", kinds.read_file("campaigns", settings)) == CampaignConfig()


def test_snapshot_generic_and_compatible(sbr_rules: ProjectRules) -> None:
    snapshot = ConfigSnapshot.of(sbr_rules, retention=RetentionConfig(raw_items_days=30))
    assert snapshot.rules is sbr_rules and snapshot.get("rules") is sbr_rules
    assert snapshot.retention.raw_items_days == 30
    assert snapshot.campaigns == CampaignConfig()
    assert snapshot.rules_version == 0 and snapshot.version("retention") == 0
    assert snapshot.digest("rules", "retention") != snapshot.digest("rules")
    assert snapshot.alerting_secrets == {}


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()
    org_mod.set_current(None)


async def test_runtime_reloads_new_kinds(
    sessions: async_sessionmaker[AsyncSession],
    clean_db: str,
    sbr_rules_path: Path,
    tmp_path: Path,
) -> None:
    retention = tmp_path / "retention.yaml"
    retention.write_text("raw_items_days: 60\n", encoding="utf-8")
    settings = Settings(
        database_url=clean_db, rules_path=sbr_rules_path, retention_config=retention
    )
    runtime = await ConfigRuntime.start(settings, sessions, process="worker@t")
    assert runtime.snapshot.retention.raw_items_days == 60
    assert runtime.snapshot.version("retention") == 0
    async with sessions.begin() as session:
        await revisions.append(
            session,
            "campaigns",
            kinds.from_data("campaigns", {"max_share": 20}),
            base_version=0,
            user="ops",
            note=None,
            now=NOW,
        )
    assert await runtime.refresh() is True
    assert runtime.snapshot.campaigns.max_share == 20
    assert runtime.snapshot.version("campaigns") == 1
    async with sessions() as session:
        reported = {row.kind for row in await revisions.statuses(session)}
    assert {"retention", "campaigns", "rules", "organization", "alerting"} <= reported


async def test_static_runtime_refresh_keeps_file_kinds(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    runtime = ConfigRuntime.static(sbr_rules, sessions=sessions)
    await runtime.refresh()
    assert runtime.snapshot.rules is sbr_rules
    assert runtime.errors["rules"] is None
    assert runtime.errors["retention"] is None
