import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.cli import main
from opti.db.engine import make_sessionmaker
from opti.db.models import ConnectorRun

MARK = "s5c-retention-test"


async def _count(db_url: str, *, add: bool = False) -> int:
    engine = create_async_engine(db_url)
    try:
        async with make_sessionmaker(engine)() as s, s.begin():
            if add:
                old = datetime.now(UTC) - timedelta(days=200)
                s.add(ConnectorRun(connector_id="crtsh", started_at=old, ended_at=old, status="ok", items=0,
                                   errors=0, message=MARK))  # fmt: skip
                await s.flush()
            n = await s.scalar(
                select(func.count()).select_from(ConnectorRun).where(ConnectorRun.message == MARK)
            )
    finally:
        await engine.dispose()
    return int(n or 0)


@pytest.mark.db
def test_retention_dry_run(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # clean_db：测试结束后清空各表（本测试真的执行清理并写审计日志，不能留给其他测试）
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    assert asyncio.run(_count(clean_db, add=True)) == 1
    assert main(["retention", "--dry-run"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True and out["connector_runs"] >= 1
    assert asyncio.run(_count(clean_db)) == 1  # 试运行没有删除
    assert main(["retention"]) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is False
    assert asyncio.run(_count(clean_db)) == 0


@pytest.mark.db
def test_dsar_cli(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    assert main(["dsar", "--name", "Nobody Here"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (
        out["erased"] is False
        and out["counts"]["findings"] == 0
        and len(out["subject_sha256"]) == 64
    )
    assert "Nobody" not in json.dumps(out)
    assert main(["dsar", "--name", "Nobody Here", "--erase"]) == 2  # 缺少 --confirm
    assert "--confirm" in capsys.readouterr().err
    assert main(["dsar", "--name", "ab"]) == 2  # 太短


@pytest.mark.db
def test_acceptance_cli(clean_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                        capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    watcher_file = tmp_path / "watcher.txt"
    watcher_file.write_text("sbr-missed.top\n", encoding="utf-8")
    code = main(["--rules", "config/projects/sample-brand/keywords.yaml", "acceptance", "--out", str(tmp_path),
                 "--watcher", str(watcher_file)])  # fmt: skip
    assert code in (0, 1)
    md = next(tmp_path.glob("acceptance-*.md")).read_text(encoding="utf-8")
    data = json.loads(next(tmp_path.glob("acceptance-*.json")).read_text(encoding="utf-8"))
    assert "# MVP 验收报告" in md and data["project"] == "sample-brand-protection"
    assert {c["key"] for c in data["checks"]} >= {"mttd_ct", "watcher", "availability"}
    assert (code == 1) == any(c["status"] == "fail" for c in data["checks"])
    assert "# MVP 验收报告" in capsys.readouterr().out
