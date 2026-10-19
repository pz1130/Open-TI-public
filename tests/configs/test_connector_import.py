import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti.configs import connector_import, kinds, revisions
from opti.configs import secrets as config_secrets
from opti.core.secretbox import Keyring, generate_key
from opti.db.engine import make_sessionmaker
from opti.db.models import AuditLog, ConfigSecret

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 13, tzinfo=UTC)
OTX = {
    "enabled": True,
    "license_approved": True,
    "license_ref": "LEGAL-1",
    "plan": "free",
    "config": {},
}


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()


def _keyring() -> Keyring:
    k = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    assert k is not None
    return k


def _legacy(state: Path, keyring: Keyring | None, instances: dict, secrets: dict) -> Path:
    def enc(cid: str, name: str, value: str | None) -> str | None:
        if value is None:
            return None
        assert keyring is not None
        return base64.b64encode(keyring.encrypt(value, aad=f"connector:{cid}:{name}")).decode()

    data = {
        "instances": instances,
        "secrets": {
            cid: {n: enc(cid, n, v) for n, v in vals.items()} for cid, vals in secrets.items()
        },
    }
    path = state / "connector-config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


async def test_imports_settings_secrets_and_renames_file(sessions, tmp_path: Path) -> None:
    keyring = _keyring()
    path = _legacy(
        tmp_path,
        keyring,
        {"otx": OTX},
        {"otx": {"api_key": "web-key"}, "urlscan": {"api_key": None}},
    )
    done = await connector_import.import_legacy(sessions, tmp_path, keyring, NOW)
    assert done == connector_import.Imported(
        connectors=1, secrets=["otx:api_key", "urlscan:api_key"]
    )
    assert not path.exists() and (tmp_path / "connector-config.json.migrated").exists()
    async with sessions() as s:
        row = await revisions.latest(s, "connectors")
        assert row is not None and row.version == 1 and row.created_by == "system"
        assert row.note == "从 connector-config.json 导入"
        assert kinds.parse("connectors", row.content).connectors["otx"].license_ref == "LEGAL-1"
        values = await config_secrets.resolve(
            s,
            "connectors",
            {"otx:api_key", "urlscan:api_key"},
            keyring,
            fallback={},
            stored_only=True,
        )
        assert values.values == {"otx:api_key": "web-key", "urlscan:api_key": None}
        audit = await s.scalar(select(AuditLog).where(AuditLog.action == "config.imported"))
        assert audit is not None and audit.detail == {
            "kind": "connectors", "connectors": 1, "secrets": ["otx:api_key", "urlscan:api_key"],
        }  # fmt: skip
    # 重复执行：文件已改名，什么都不做
    assert await connector_import.import_legacy(sessions, tmp_path, keyring, NOW) is None


async def test_skips_when_database_already_has_connector_settings(sessions, tmp_path: Path) -> None:
    path = _legacy(tmp_path, None, {"otx": OTX}, {})
    async with sessions.begin() as s:
        await revisions.append(s, "connectors", "", base_version=0, user="t", note=None, now=NOW)
    assert await connector_import.import_legacy(sessions, tmp_path, None, NOW) is None
    assert path.exists()


async def test_encrypted_secrets_without_key_stop_the_upgrade(sessions, tmp_path: Path) -> None:
    path = _legacy(tmp_path, _keyring(), {"otx": OTX}, {"otx": {"api_key": "web-key"}})
    with pytest.raises(connector_import.ImportFailed, match="OPTI_ENCRYPTION_KEY"):
        await connector_import.import_legacy(sessions, tmp_path, None, NOW)
    with pytest.raises(connector_import.ImportFailed, match="无法解密"):
        await connector_import.import_legacy(sessions, tmp_path, _keyring(), NOW)
    assert path.exists()
    async with sessions() as s:
        assert await revisions.latest(s, "connectors") is None
        assert await s.scalar(select(ConfigSecret)) is None


async def test_invalid_entries_stop_the_upgrade_without_partial_import(
    sessions, tmp_path: Path
) -> None:
    path = _legacy(tmp_path, None, {"otx": OTX, "gone_source": {"enabled": True}}, {})
    with pytest.raises(connector_import.ImportFailed, match=r"connectors\.gone_source"):
        await connector_import.import_legacy(sessions, tmp_path, None, NOW)
    assert path.exists()
    async with sessions() as s:
        assert await revisions.latest(s, "connectors") is None


async def test_unreadable_file_stops_the_upgrade(sessions, tmp_path: Path) -> None:
    (tmp_path / "connector-config.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(connector_import.ImportFailed, match="格式"):
        await connector_import.import_legacy(sessions, tmp_path, None, NOW)


@pytest.mark.parametrize(
    "secrets",
    [
        {"otx": []},
        {"otx": None},
        {"otx": {"api_key": 42}},
        {"otx": {"api_key": False}},
        {"gone_source": {}},
        {"otx": {"unknown": None}},
    ],
)
async def test_malformed_secret_entries_leave_everything_unchanged(
    sessions, tmp_path: Path, secrets: dict
) -> None:
    path = tmp_path / connector_import.FILE_NAME
    original = json.dumps({"instances": {"otx": OTX}, "secrets": secrets})
    path.write_text(original, encoding="utf-8")
    with pytest.raises(connector_import.ImportFailed):
        await connector_import.import_legacy(sessions, tmp_path, _keyring(), NOW)
    assert path.read_text(encoding="utf-8") == original
    async with sessions() as s:
        assert await revisions.latest(s, "connectors") is None
        assert await s.scalar(select(ConfigSecret)) is None
        assert await s.scalar(select(AuditLog)) is None


async def test_existing_revision_skips_even_an_invalid_legacy_file(
    sessions, tmp_path: Path
) -> None:
    path = tmp_path / connector_import.FILE_NAME
    path.write_text("not json", encoding="utf-8")
    async with sessions.begin() as s:
        await revisions.append(s, "connectors", "", base_version=0, user="t", note=None, now=NOW)
    assert await connector_import.import_legacy(sessions, tmp_path, None, NOW) is None
    assert path.read_text(encoding="utf-8") == "not json"
