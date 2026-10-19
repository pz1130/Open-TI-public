import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.api import security
from opti.cli import amain, main
from opti.db.engine import make_sessionmaker
from opti.db.models import AuditLog

PASSWORD = "correct horse battery staple"


def test_api_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["api-schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert "/api/v1/alerts" in schema["paths"] and "/api/v1/rules/test" in schema["paths"]


@pytest.mark.db
async def test_user_commands_and_audit_verify(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 账号命令走 amain（异步），测试里直接 await，不经过 main() 里的 asyncio.run
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    monkeypatch.setenv("OPTI_NEW_PASSWORD", PASSWORD)
    assert await amain(["user-add", "alice", "--role", "analyst", "--display-name", "Alice"]) == 0
    assert await amain(["user-add", "alice", "--role", "analyst"]) == 2
    assert await amain(["user-add", "bob", "--role", "root"]) == 2
    monkeypatch.setenv("OPTI_NEW_PASSWORD", "short")
    assert await amain(["user-passwd", "alice"]) == 2
    assert await amain(["user-disable", "alice"]) == 0
    assert await amain(["audit-verify"]) == 0
    assert "哈希链完整" in capsys.readouterr().out
    engine = create_async_engine(clean_db)
    async with make_sessionmaker(engine).begin() as s:
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
        assert list(actions) == ["user.create", "user.disable"]
        assert (
            await security.authenticate(s, "alice", PASSWORD, datetime.now(UTC)) is None
        )  # 已停用
    await engine.dispose()


@pytest.mark.db
async def test_user_list(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    monkeypatch.setenv("OPTI_NEW_PASSWORD", PASSWORD)
    assert await amain(["user-add", "breakglass", "--role", "platform_admin"]) == 0
    capsys.readouterr()
    assert await amain(["user-list"]) == 0
    [row] = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert row == {"username": "breakglass", "auth_source": "local", "roles": ["platform_admin"],
                   "active": True, "last_login_at": None}  # fmt: skip
