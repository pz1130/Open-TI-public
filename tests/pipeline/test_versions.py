import asyncio
from pathlib import Path

import pytest

from opti import organization as org_mod
from opti.configs import kinds, revisions
from opti.configs.connectors import ConnectorOverrides
from opti.configs.runtime import ConfigSnapshot
from opti.core.config import ProjectRules
from opti.core.policy import OperationsConfig
from opti.pipeline import app as app_mod
from opti.pipeline.app import build_app
from opti.pipeline.versions import Pipeline, PipelineCache
from opti.settings import Settings


async def test_rebuilds_on_new_snapshot_and_closes_old_after_grace(sbr_rules: ProjectRules) -> None:
    built: list[str] = []
    closed: list[str] = []

    def build(snap: ConfigSnapshot) -> tuple[Pipeline, list]:
        name = snap.rules.project
        built.append(name)

        async def close() -> None:
            closed.append(name)

        return Pipeline(enrichment=object(), processor=object()), [close]  # type: ignore[arg-type]

    cache = PipelineCache(build, grace=0.01)
    first = ConfigSnapshot.of(sbr_rules)
    assert cache.get(first) is cache.get(first)
    second = ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "next"}))
    cache.get(second)
    assert built == [sbr_rules.project, "next"] and closed == []
    await asyncio.sleep(0.05)
    assert closed == [sbr_rules.project]
    await cache.close()
    assert closed == [sbr_rules.project, "next"]


async def test_connector_or_timeout_change_rebuilds_enrichment(sbr_rules: ProjectRules) -> None:
    built: list[str] = []
    cache = PipelineCache(_flaky_build(built))
    original = cache.get(ConfigSnapshot.of(sbr_rules))
    changed = cache.get(
        ConfigSnapshot.of(
            sbr_rules,
            connectors=ConnectorOverrides.model_validate(
                {
                    "connectors": {"tls": {"enabled": True, "license_approved": True}},
                }
            ),
        )
    )
    assert changed is not original
    changed_timeout = cache.get(
        ConfigSnapshot.of(
            sbr_rules,
            operations=OperationsConfig.model_validate(
                {
                    "scanning": {"enrichment_timeout_seconds": 90},
                }
            ),
        )
    )
    assert changed_timeout is not changed
    await cache.close()


def _flaky_build(built: list[str]):  # type: ignore[no-untyped-def]
    def build(snap: ConfigSnapshot) -> tuple[Pipeline, list]:
        built.append(snap.rules.project)
        if snap.rules.project.startswith("broken"):
            raise RuntimeError("rebuild failed")
        return Pipeline(enrichment=object(), processor=object()), []  # type: ignore[arg-type]

    return build


async def test_failed_rebuild_is_not_retried_for_every_get(sbr_rules: ProjectRules) -> None:
    built: list[str] = []
    cache = PipelineCache(_flaky_build(built))
    good = cache.get(ConfigSnapshot.of(sbr_rules))
    broken = ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "broken"}))
    for _ in range(100):
        assert cache.get(broken) is good
    assert built == [sbr_rules.project, "broken"]
    await cache.close()


async def test_failed_rebuild_retries_after_interval_or_on_new_config(
    sbr_rules: ProjectRules,
) -> None:
    built: list[str] = []
    now = [0.0]
    cache = PipelineCache(_flaky_build(built), retry_seconds=60, clock=lambda: now[0])
    good = cache.get(ConfigSnapshot.of(sbr_rules))
    broken = ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "broken"}))
    cache.get(broken)
    now[0] = 59.0
    assert cache.get(broken) is good and built.count("broken") == 1
    now[0] = 61.0
    assert cache.get(broken) is good and built.count("broken") == 2
    other = ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "broken-again"}))
    cache.get(other)
    assert built[-1] == "broken-again"
    fixed = ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "fixed"}))
    assert cache.get(fixed) is not good
    await cache.close()


@pytest.mark.db
async def test_failed_rebuild_keeps_processor_closes_client_and_records_error(
    clean_db: str, sbr_rules: ProjectRules, sbr_rules_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = sbr_rules_path.read_text(encoding="utf-8")
    closed: list[str] = []

    def fake_create(
        registry: object, rules: ProjectRules, paths: object, closers: list, **kwargs: object
    ) -> dict[str, object]:
        async def close() -> None:
            closed.append(rules.project)

        closers.append(close)
        if rules.project == "broken":
            raise RuntimeError("rebuild failed")
        return {}

    monkeypatch.setattr(app_mod, "_create_enrichers", fake_create)
    application = await build_app(
        Settings(database_url=clean_db, rules_path=sbr_rules_path), process="worker@t", sinks=[]
    )
    try:
        previous = application.processor
        application.config.apply(
            ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "broken"}))
        )
        got = application.processor
        assert got is previous
        deadline = asyncio.get_running_loop().time() + 5
        while "broken" not in closed and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        assert "broken" in closed and sbr_rules.project not in closed

        async def errors() -> list[str | None]:
            async with application.sessions() as s:
                rows = [row for row in await revisions.statuses(s) if row.process == "worker@t"]
            assert {row.kind for row in rows} == set(kinds.KINDS)
            return [row.error for row in rows]

        found: list[str | None] = []
        while asyncio.get_running_loop().time() < deadline:
            found = await errors()
            if found and all(found):
                break
            await asyncio.sleep(0.01)
        assert found and all(
            error and document not in error and "SAMPLE-AUTH-PENDING" not in error
            for error in found
        )
        assert all(error and "rebuild failed" in error for error in found)

        application.config.apply(
            ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "fixed"}))
        )
        assert application.processor is not previous
        cleared: list[str | None] = ["pending"]
        while asyncio.get_running_loop().time() < deadline:
            cleared = await errors()
            if cleared and all(error is None for error in cleared):
                break
            await asyncio.sleep(0.01)
        assert cleared and all(error is None for error in cleared)
    finally:
        org_mod.set_current(None)
        await application.close()
