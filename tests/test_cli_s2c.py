import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.cli import amain
from opti.db.engine import make_sessionmaker
from opti.db.models import AuditLog


@pytest.mark.db
async def test_token_commands(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    assert (
        await amain(["token-create", "dns-firewall", "--scope", "blocklist:export", "--days", "30"])
        == 0
    )
    token = capsys.readouterr().out.strip()
    assert token.startswith("opti_") and len(token) > 40
    assert await amain(["token-create", "dns-firewall", "--scope", "blocklist:export"]) == 2  # 重名
    assert await amain(["token-create", "x1", "--scope", "admin"]) == 2  # 未知作用域
    assert await amain(["token-create", "x2", "--scope", "blocklist:export", "--days", "9999"]) == 2
    capsys.readouterr()
    assert await amain(["token-list"]) == 0
    [row] = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert row["name"] == "dns-firewall" and row["prefix"] == token[:12] and row["revoked"] is False
    assert token not in json.dumps(row)
    assert await amain(["token-revoke", "dns-firewall"]) == 0
    assert await amain(["token-revoke", "dns-firewall"]) == 2  # 已吊销
    engine = create_async_engine(clean_db)
    async with make_sessionmaker(engine)() as s:
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
    await engine.dispose()
    assert list(actions) == ["token.create", "token.revoke"]
