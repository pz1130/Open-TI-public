import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from opti.configs import kinds, revisions
from opti.db.engine import make_sessionmaker
from opti.pipeline.schedule import BuiltinScheduleSource, ManifestScheduleSource
from opti.sdk.registry import Registry
from opti.sdk.runtime import RuntimePaths
from opti.settings import Settings


async def test_invalid_instance_does_not_drop_other_schedules(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = tmp_path / "connectors"
    cfg.mkdir()
    (cfg / "crtsh.yaml").write_text("bogus: true\n", encoding="utf-8")
    (cfg / "dnstwist.yaml").write_text("enabled: true\nlicense_approved: true\n", encoding="utf-8")
    source = ManifestScheduleSource(Registry(), RuntimePaths(config_dir=cfg))
    with caplog.at_level(logging.WARNING, logger="opti.schedule"):
        schedules = {s.args[0]: s.cron for s in await source.get_schedules()}
    assert schedules["dnstwist"] == "0 3 * * *"
    assert "crtsh" not in schedules
    assert "已跳过定时调度" in caplog.text
    assert "crtsh" in caplog.text


async def _save_dnstwist(url: str, enabled: bool, base: int) -> None:
    engine = create_async_engine(url)
    text = kinds.from_data(
        "connectors",
        {
            "connectors": {
                "dnstwist": {"enabled": enabled, "license_approved": True, "license_ref": "L"}
            }
        },
    )
    async with make_sessionmaker(engine).begin() as s:
        await revisions.append(s, "connectors", text, base_version=base, user="t", note=None,
                               now=datetime.now(UTC))  # fmt: skip
    await engine.dispose()


@pytest.mark.db
async def test_web_settings_turn_schedules_on_and_off(
    clean_db: str, sbr_rules_path: Path, tmp_path: Path
) -> None:
    cfg = tmp_path / "connectors"
    cfg.mkdir()  # YAML 里什么都没启用
    settings = Settings(database_url=clean_db, rules_path=sbr_rules_path, config_dir=cfg)
    await _save_dnstwist(clean_db, True, 0)
    source = ManifestScheduleSource(Registry(), RuntimePaths(config_dir=cfg), settings=settings)
    await source.startup()
    try:
        assert "dnstwist" in {s.args[0] for s in await source.get_schedules()}
        await _save_dnstwist(clean_db, False, 1)
        assert source.config is not None and await source.config.refresh() is True
        assert "dnstwist" not in {s.args[0] for s in await source.get_schedules()}
    finally:
        await source.shutdown()


async def test_without_database_the_source_uses_yaml_only(tmp_path: Path) -> None:
    source = ManifestScheduleSource(
        Registry(), RuntimePaths(config_dir=tmp_path), settings=Settings()
    )
    await source.startup()
    assert source.config is None
    await source.shutdown()


@pytest.mark.db
async def test_business_schedule_updates_keep_one_stable_task_id(
    clean_db: str, sbr_rules_path: Path, tmp_path: Path
) -> None:
    source = ManifestScheduleSource(
        Registry(),
        RuntimePaths(config_dir=tmp_path),
        settings=Settings(database_url=clean_db, rules_path=sbr_rules_path),
    )
    await source.startup()
    builtin = BuiltinScheduleSource(source)
    try:
        before = await builtin.get_schedules()
        assert len({s.schedule_id for s in before}) == len(before)
        engine = create_async_engine(clean_db)
        async with make_sessionmaker(engine).begin() as s:
            await revisions.append(
                s,
                "operations",
                kinds.from_data(
                    "operations",
                    {
                        "schedules": {"recheck_watchlist": "*/20 * * * *"},
                    },
                ),
                base_version=0,
                user="admin",
                note=None,
                now=datetime.now(UTC),
            )
        await engine.dispose()
        assert source.config is not None
        assert await source.config.refresh()
        changed = [
            s for s in await builtin.get_schedules() if s.task_name == "opti.recheck_watchlist"
        ]
        assert len(changed) == 1 and changed[0].cron == "*/20 * * * *"
        assert changed[0].schedule_id == "builtin:recheck_watchlist"
    finally:
        await source.shutdown()
