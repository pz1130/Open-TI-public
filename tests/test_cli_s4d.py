import base64
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from opti.cli import amain
from opti.core.secretbox import Keyring
from opti.db.engine import make_sessionmaker
from opti.db.models import LlmProvider
from opti.pipeline import llm_runtime

NOW = datetime(2026, 10, 10, tzinfo=UTC)
OLD, NEW = bytes(range(32)), bytes(range(32, 64))
KEY = "sk-" + "cli-" + "abcdefghijklmnop"


async def test_encryption_key_gen(capsys: pytest.CaptureFixture[str]) -> None:
    assert await amain(["encryption-key-gen"]) == 0
    out = capsys.readouterr()
    assert len(base64.b64decode(out.out.strip(), validate=True)) == 32
    assert "OPTI_ENCRYPTION_KEY" in out.err


async def test_llm_commands_need_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OPTI_DATABASE_URL", raising=False)
    for argv in (["llm-check"], ["eval-texts", "--llm"], ["eval-code"], ["rekey"]):
        assert await amain(argv) == 2
        assert "OPTI_DATABASE_URL" in capsys.readouterr().err


@pytest.mark.db
async def test_llm_commands_when_disabled(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    assert await amain(["llm-check"]) == 0
    assert "主用供应商" in capsys.readouterr().out
    assert await amain(["eval-texts", "--llm"]) == 2
    assert "主用供应商" in capsys.readouterr().err
    assert await amain(["eval-code"]) == 2
    assert "主用供应商" in capsys.readouterr().err


@pytest.mark.db
async def test_rekey(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    async with sessions.begin() as s:
        row = LlmProvider(name="DeepSeek", preset="deepseek", base_url="https://api.deepseek.com/v1",
                          model="deepseek-chat", json_mode=True, temperature=0.0, timeout_seconds=60,
                          created_at=NOW, updated_at=NOW)  # fmt: skip
        s.add(row)
        await s.flush()
        row.api_key_enc = Keyring(OLD).encrypt(KEY, aad=llm_runtime.aad(row.id, "api_key"))
        pid = row.id
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    monkeypatch.setenv("OPTI_ENCRYPTION_KEY", base64.b64encode(NEW).decode())
    monkeypatch.delenv("OPTI_ENCRYPTION_KEY_PREVIOUS", raising=False)
    assert await amain(["rekey"]) == 2  # 缺旧钥：无法解密，不改任何字段
    assert "PREVIOUS" in capsys.readouterr().err
    monkeypatch.setenv("OPTI_ENCRYPTION_KEY_PREVIOUS", base64.b64encode(OLD).decode())
    assert await amain(["rekey"]) == 0
    assert capsys.readouterr().out.strip() == (
        "已用当前主密钥重新加密 1 个大模型字段、0 个配置密钥（含连接器凭据）"
    )
    async with sessions() as s:
        got = await s.get(LlmProvider, pid)
        assert got is not None and got.api_key_enc is not None
        assert Keyring(NEW).decrypt(got.api_key_enc, aad=llm_runtime.aad(pid, "api_key")) == KEY
    await engine.dispose()
