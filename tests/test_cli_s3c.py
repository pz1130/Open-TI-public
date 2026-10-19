import io
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.cli import amain
from opti.core.config import load_project_rules
from opti.core.scoring import Category, Score, Severity
from opti.core.secrets import fingerprint
from opti.db import repo
from opti.db.engine import make_sessionmaker
from opti.db.models import AuditLog
from opti.settings import Settings

CANDIDATE = "AKIA" + "QYLPMN5HTWX2BVFC"


@pytest.mark.db
async def test_secret_match(clean_db: str, monkeypatch: pytest.MonkeyPatch,
                            capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    rules = load_project_rules(Settings.from_env().rules_path)
    digest = fingerprint(CANDIDATE)
    engine = create_async_engine(clean_db)
    now = datetime.now(UTC)
    async with make_sessionmaker(engine).begin() as session:
        await repo.upsert_project(session, rules)
        entity = await repo.upsert_entity(session, "repo", "github.com/dev2/deploy", now)
        secret = {"rule": "aws-access-token", "file": "config/app.env", "line": 2,
                  "prefix": "AKIA", "fingerprint": digest,
                  "url": "https://github.com/dev2/deploy/blob/c/config/app.env#L2"}  # fmt: skip
        await repo.upsert_finding(
            session,
            project_id=rules.project,
            entity=entity,
            score=Score(90, Severity.CRITICAL, Category.SECRET_LEAK, {}),
            match={"repo": "dev2/deploy", "hits": [], "scan": {"secrets": [secret]}},
            source="secret_scan",
            now=now,
        )
    monkeypatch.setattr("sys.stdin", io.StringIO(CANDIDATE + "\n"))
    assert await amain(["secret-match"]) == 0
    [row] = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert row["repo"] == "dev2/deploy" and row["file"] == "config/app.env" and row["line"] == 2
    monkeypatch.setattr("sys.stdin", io.StringIO("not-the-key\n"))
    assert await amain(["secret-match"]) == 1
    async with make_sessionmaker(engine)() as session:
        details = [
            row.detail
            for row in (
                await session.scalars(select(AuditLog).where(AuditLog.action == "secret.match"))
            ).all()
        ]
    await engine.dispose()
    assert (
        details[0] == {"fingerprint_prefix": digest[:12], "matches": 1}
        and details[1]["matches"] == 0
    )
    assert CANDIDATE not in json.dumps(details)
