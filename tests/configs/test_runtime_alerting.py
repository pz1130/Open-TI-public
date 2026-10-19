from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti import organization as org_mod
from opti.configs import kinds, revisions, secrets
from opti.configs.runtime import ConfigRuntime
from opti.core.secretbox import Keyring, generate_key
from opti.db.engine import make_sessionmaker
from opti.settings import Settings

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 12, tzinfo=UTC)
HOOK = "channel:teams:webhook_url"


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()
    org_mod.set_current(None)


@pytest.fixture
def settings(clean_db: str, sbr_rules_path: Path, tmp_path: Path) -> Settings:
    alerting = tmp_path / "alerting.yaml"
    alerting.write_text("immediate: [critical, high]\nteams:\n  enabled: true\n", encoding="utf-8")
    return Settings(database_url=clean_db, rules_path=sbr_rules_path, alerting_config=alerting)


@pytest.fixture
def keyring() -> Keyring:
    k = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    assert k is not None
    return k


async def test_start_reads_file_and_env_fallback(sessions, settings, keyring, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPTI_SECRET_ALERTING_TEAMS_WEBHOOK_URL", "https://env.example/hook")
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t", keyring=keyring)
    snap = rt.snapshot
    assert [c.id for c in snap.alerting.channels] == ["teams"] and snap.alerting_version == 0
    assert snap.alerting_secrets[HOOK] == "https://env.example/hook"
    async with sessions() as s:
        kinds_reported = {r.kind for r in await revisions.statuses(s)}
    assert kinds_reported == set(kinds.KINDS)


async def test_secret_only_change_refreshes(sessions, settings, keyring) -> None:  # type: ignore[no-untyped-def]
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t", keyring=keyring)
    before = rt.snapshot.alerting_digest
    async with sessions.begin() as s:
        await secrets.write(
            s,
            "alerting",
            {HOOK: "https://db.example/hook-0001"},
            keyring=keyring,
            user="ops",
            now=NOW,
        )
    assert await rt.refresh() is True
    assert rt.snapshot.alerting_secrets[HOOK] == "https://db.example/hook-0001"
    assert rt.snapshot.alerting_version == 0 and rt.snapshot.alerting_digest != before
    assert await rt.refresh() is False


async def test_saved_alerting_revision_applies(sessions, settings, keyring) -> None:  # type: ignore[no-untyped-def]
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t", keyring=keyring)
    data = kinds.to_data("alerting", rt.snapshot.alerting)
    data["channels"] = [
        {"id": "secops", "name": "值班", "type": "teams", "severities": ["critical"]}
    ]
    async with sessions.begin() as s:
        await revisions.append(s, "alerting", kinds.from_data("alerting", data), base_version=0,
                               user="ops", note=None, now=NOW)  # fmt: skip
    assert await rt.refresh() is True
    assert [c.id for c in rt.snapshot.alerting.channels] == [
        "secops"
    ] and rt.snapshot.alerting_version == 1
    assert set(rt.snapshot.alerting_secrets) == {
        "smtp_username",
        "smtp_password",
        "channel:secops:webhook_url",
    }


async def test_undecryptable_secret_is_reported(sessions, settings, keyring) -> None:  # type: ignore[no-untyped-def]
    other = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    async with sessions.begin() as s:
        await secrets.write(
            s,
            "alerting",
            {HOOK: "https://db.example/hook-0001"},
            keyring=other,
            user="ops",
            now=NOW,
        )
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t", keyring=keyring)
    assert rt.snapshot.alerting_secrets[HOOK] is None
    assert rt.errors["alerting"] is not None and "无法解密" in rt.errors["alerting"]
    assert "hook-0001" not in rt.errors["alerting"]
