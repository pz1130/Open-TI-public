from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti import organization as org_mod
from opti.configs import kinds, revisions
from opti.configs import secrets as config_secrets
from opti.configs.runtime import ConfigRuntime
from opti.core.secretbox import Keyring, generate_key
from opti.db.engine import make_sessionmaker
from opti.sdk.context import EnvSecretProvider
from opti.sdk.registry import load_file_instance, load_instance_config
from opti.settings import Settings

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 13, tzinfo=UTC)
CONFIG_DIR = Path("config/connectors")


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()
    org_mod.set_current(None)


def _keyring() -> Keyring:
    k = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    assert k is not None
    return k


def _doc(enabled: bool) -> str:
    return kinds.from_data(
        "connectors", {"connectors": {"otx": {"enabled": enabled, "plan": "free"}}}
    )


async def test_start_installs_overrides_and_stored_secrets(
    sessions, clean_db, sbr_rules_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPTI_SECRET_URLSCAN_API_KEY", "env-only")
    keyring = _keyring()
    async with sessions.begin() as s:
        await revisions.append(
            s, "connectors", _doc(True), base_version=0, user="t", note=None, now=NOW
        )
        await config_secrets.write(
            s, "connectors", {"otx:api_key": "web-key"}, keyring=keyring, user="t", now=NOW
        )
    settings = Settings(database_url=clean_db, rules_path=sbr_rules_path)
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t", keyring=keyring)
    assert rt.snapshot.version("connectors") == 1
    assert load_instance_config(CONFIG_DIR, "otx").enabled is True
    assert EnvSecretProvider().get("otx", "api_key") == "web-key"
    # 快照只带库中的密钥；环境变量由读取方兜底，不进快照（网关不会把它下发给采集节点）
    assert "urlscan:api_key" not in rt.snapshot.secrets("connectors")
    assert EnvSecretProvider().get("urlscan", "api_key") == "env-only"


async def test_refresh_installs_new_version_and_secret_only_changes(sessions, sbr_rules) -> None:
    keyring = _keyring()
    rt = ConfigRuntime.static(sbr_rules, sessions=sessions, keyring=keyring)
    async with sessions.begin() as s:
        await revisions.append(
            s, "connectors", _doc(True), base_version=0, user="t", note=None, now=NOW
        )
    assert await rt.refresh() is True
    assert load_instance_config(CONFIG_DIR, "otx").enabled is True
    async with sessions.begin() as s:
        await config_secrets.write(
            s, "connectors", {"otx:api_key": "rotated"}, keyring=keyring, user="t", now=NOW
        )
    assert await rt.refresh() is True
    assert EnvSecretProvider().get("otx", "api_key") == "rotated"


async def test_undecryptable_secret_is_reported(sessions, clean_db, sbr_rules_path) -> None:
    async with sessions.begin() as s:
        await config_secrets.write(
            s, "connectors", {"otx:api_key": "x" * 20}, keyring=_keyring(), user="t", now=NOW
        )
    settings = Settings(database_url=clean_db, rules_path=sbr_rules_path)
    rt = await ConfigRuntime.start(settings, sessions, process="api@t", keyring=_keyring())
    assert "otx:api_key" in (rt.errors["connectors"] or "")
    assert EnvSecretProvider().get("otx", "api_key") is None


async def test_database_down_at_start_falls_back_to_yaml_and_environment(
    sbr_rules_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPTI_SECRET_OTX_API_KEY", "env-key")
    engine = create_async_engine("postgresql+asyncpg://opti:x@127.0.0.1:1/none")
    settings = Settings(
        database_url="postgresql+asyncpg://opti:x@127.0.0.1:1/none", rules_path=sbr_rules_path
    )
    try:
        rt = await ConfigRuntime.start(settings, make_sessionmaker(engine), process="api@t")
    finally:
        await engine.dispose()
        org_mod.set_current(None)
    assert rt.snapshot.connectors.connectors == {} and rt.snapshot.secrets("connectors") == {}
    assert load_instance_config(CONFIG_DIR, "otx") == load_file_instance(CONFIG_DIR, "otx")
    assert EnvSecretProvider().get("otx", "api_key") == "env-key"
