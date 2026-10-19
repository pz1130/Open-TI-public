import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.cli import main
from opti.configs import kinds, revisions
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.engine import make_sessionmaker
from opti.db.models import Finding
from opti.sdk.models import RawItem


def test_db_commands_require_database_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OPTI_DATABASE_URL", raising=False)
    assert main(["report-daily"]) == 2
    assert "OPTI_DATABASE_URL" in capsys.readouterr().err


@pytest.mark.db
def test_db_upgrade_and_report(
    db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", db_url)
    monkeypatch.setenv("OPTI_STATE_DIR", str(tmp_path))  # 不碰开发机 data/ 里的连接器设置
    assert main(["db-upgrade"]) == 0
    assert main(["report-daily"]) == 0
    assert "/reports/" in capsys.readouterr().out
    assert main(["report-monthly", "--month", "2026-09"]) == 0
    assert "/reports/" in capsys.readouterr().out
    assert main(["report-monthly", "--month", "2099-01"]) == 2  # 未结束的月份
    assert "尚未结束" in capsys.readouterr().err


@pytest.mark.db
def test_run_blocked_connector_exits_3(
    db_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", db_url)
    assert main(["run", "nrd", "--max-items", "1"]) == 3
    assert "license_not_approved" in capsys.readouterr().err


async def _seed_unsampled(url: str, rules: ProjectRules, now: datetime) -> int:
    """模拟升级前的存量：发现有告警，但还没有 first_alerted_at 与样本。"""
    engine = create_async_engine(url)
    try:
        async with make_sessionmaker(engine).begin() as s:
            await repo.upsert_project(s, rules)
            item = RawItem(connector_id="certstream", source_item_id="sbr-a.top", fetched_at=now, url=None,
                           payload={"cert": {"seen": (now - timedelta(hours=2)).timestamp()}},
                           project_ids=(rules.project,))  # fmt: skip
            await repo.insert_raw_item(s, item)
            entity = await repo.upsert_entity(s, "domain", "sbr-a.top", now)
            score = Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 70})
            up = await repo.upsert_finding(s, project_id=rules.project, entity=entity, score=score,
                                           match={"reasons": []}, source="certstream", now=now)  # fmt: skip
            await repo.add_observation(s, up.finding, item, 70, now)
            await repo.open_alert(s, up.finding, Severity.HIGH, now)
            up.finding.first_alerted_at = up.finding.mttd_source = up.finding.mttd_hours = None
            return up.finding.id
    finally:
        await engine.dispose()


async def _sample(url: str, finding_id: int) -> tuple[object, ...]:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            stmt = select(Finding.first_alerted_at, Finding.mttd_source, Finding.mttd_hours)
            return tuple((await conn.execute(stmt.where(Finding.id == finding_id))).one())
    finally:
        await engine.dispose()


@pytest.mark.db
def test_db_upgrade_backfills_mttd_samples(
    clean_db: str, sbr_rules: ProjectRules, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    now = datetime(2026, 10, 3, 8, tzinfo=UTC)
    finding_id = asyncio.run(_seed_unsampled(clean_db, sbr_rules, now))
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    monkeypatch.setenv("OPTI_STATE_DIR", str(tmp_path))  # 不碰开发机 data/ 里的连接器设置
    assert main(["db-upgrade"]) == 0
    assert "已补算 1 个已告警发现的 MTTD 样本" in capsys.readouterr().out
    assert asyncio.run(_sample(clean_db, finding_id)) == (now, "ct", 2.0)
    assert main(["db-upgrade"]) == 0
    assert "MTTD" not in capsys.readouterr().out  # 已补过的不再处理


@pytest.mark.db
def test_db_upgrade_imports_connector_file_or_stops(
    clean_db: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    monkeypatch.setenv("OPTI_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("OPTI_ENCRYPTION_KEY", raising=False)
    legacy = tmp_path / "connector-config.json"
    legacy.write_text(
        json.dumps(
            {"instances": {"otx": {"enabled": True}}, "secrets": {"otx": {"api_key": "c2VjcmV0"}}}
        ),
        encoding="utf-8",
    )
    assert main(["db-upgrade"]) == 2
    assert "OPTI_ENCRYPTION_KEY" in capsys.readouterr().err and legacy.exists()
    legacy.write_text(
        json.dumps({"instances": {"otx": {"enabled": True}}, "secrets": {}}), encoding="utf-8"
    )
    assert main(["db-upgrade"]) == 0
    assert "已导入 1 个连接器的网页设置" in capsys.readouterr().out
    assert not legacy.exists()


async def _approve_nrd(url: str) -> None:
    engine = create_async_engine(url)
    text = kinds.from_data(
        "connectors",
        {"connectors": {"nrd": {"enabled": True, "license_approved": True, "license_ref": "L-1"}}},
    )
    async with make_sessionmaker(engine).begin() as s:
        await revisions.append(s, "connectors", text, base_version=0, user="t", note=None,
                               now=datetime.now(UTC))  # fmt: skip
    await engine.dispose()


@pytest.mark.db
def test_one_off_commands_see_web_connector_settings(
    clean_db: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", clean_db)
    asyncio.run(_approve_nrd(clean_db))
    assert main(["connectors"]) == 0
    rows = {r["id"]: r for r in map(json.loads, capsys.readouterr().out.splitlines())}
    assert rows["nrd"]["runnable"] is True
