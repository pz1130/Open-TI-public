from datetime import date

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import Base
from opti.db.partitions import drop_raw_item_partitions_before, ensure_raw_item_partitions

pytestmark = pytest.mark.db

EXPECTED = {"app_user", "api_session", "audit_log", "feedback", "suppression_rule","evidence", "collector_node",
    "project", "raw_item", "entity", "finding", "finding_observation", "alert",
    "alert_finding", "watched_domain", "domain_observation", "connector_cursor", "connector_run",
}  # fmt: skip


async def test_tables_exist(session: AsyncSession) -> None:
    rows = await session.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    names = {r[0] for r in rows}
    assert names >= EXPECTED
    assert {"alembic_version", "raw_item_default"} <= names


DOCUMENT_INDEXES = frozenset({"ix_document_search_tsv", "ix_document_search_trgm"})
# 迁移里用 SQL 建的表达式索引，模型中不声明，比对模型与迁移时跳过
UNMANAGED_INDEXES = DOCUMENT_INDEXES | {"uq_dashboard_layout_default"}


def _include(name: str | None, type_: str, _parents: object) -> bool:
    if type_ == "index" and name in UNMANAGED_INDEXES:
        return False
    return not (type_ == "table" and name is not None and name.startswith("raw_item_"))


async def test_full_text_indexes_exist(session: AsyncSession) -> None:
    conn = await session.connection()
    names = set(
        (
            await conn.execute(
                text("SELECT indexname FROM pg_indexes WHERE tablename = 'document'")
            )
        ).scalars()
    )
    assert names >= DOCUMENT_INDEXES
    assert (
        await conn.scalar(text("SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'")) == 1
    )


async def test_migration_matches_models(session: AsyncSession) -> None:
    conn = await session.connection()
    diffs = await conn.run_sync(
        lambda c: compare_metadata(
            MigrationContext.configure(c, opts={"include_name": _include}), Base.metadata
        )
    )
    assert diffs == []


async def test_partitions(session: AsyncSession) -> None:
    conn = await session.connection()
    created = await ensure_raw_item_partitions(conn, date(2030, 1, 15))
    assert created == ["raw_item_2030_01", "raw_item_2030_02", "raw_item_2030_03"]
    assert await ensure_raw_item_partitions(conn, date(2030, 1, 15)) == []
    await conn.execute(
        text(
            "INSERT INTO raw_item (item_id, fetched_at, connector_id, source_item_id, payload, project_ids)"
            " VALUES ('x', '2030-02-10T00:00:00Z', 'c', 's', '{}', '{}')"
        )
    )
    where = await conn.scalar(
        text("SELECT tableoid::regclass::text FROM raw_item WHERE item_id = 'x'")
    )
    assert where == "raw_item_2030_02"
    dropped = await drop_raw_item_partitions_before(conn, date(2030, 2, 20))
    assert "raw_item_2030_01" in dropped and "raw_item_2030_02" not in dropped


async def test_partition_bounds_are_utc(session: AsyncSession) -> None:
    """会话时区非 UTC 时，UTC 月初落入当月分区，下月月初不落入。"""
    conn = await session.connection()
    await conn.execute(text("SET TIME ZONE 'America/Los_Angeles'"))
    created = await ensure_raw_item_partitions(conn, date(2030, 2, 15), months_ahead=0)
    assert created == ["raw_item_2030_02"]
    await conn.execute(
        text(
            "INSERT INTO raw_item (item_id, fetched_at, connector_id, source_item_id, payload, project_ids)"
            " VALUES ('month-start', '2030-02-01T00:00:00Z', 'c', 's', '{}', '{}'),"
            " ('next-month', '2030-03-01T00:00:00Z', 'c', 's', '{}', '{}')"
        )
    )

    async def located(item_id: str) -> str | None:
        found = await conn.scalar(
            text("SELECT tableoid::regclass::text FROM raw_item WHERE item_id = :item_id"),
            {"item_id": item_id},
        )
        return str(found) if found is not None else None

    assert await located("month-start") == "raw_item_2030_02"
    assert await located("next-month") != "raw_item_2030_02"


async def test_alert_and_run_have_s1d_columns(session: AsyncSession) -> None:
    cols = {
        (r[0], r[1])
        for r in await session.execute(
            text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_name IN ('alert', 'connector_run')"
            )
        )
    }
    assert {("alert", "evidence_status"), ("alert", "evidence_attempts")} <= cols
    assert {("connector_run", "node_id"), ("connector_run", "deadline_at")} <= cols


async def test_alert_has_triage_columns(session: AsyncSession) -> None:
    cols = {
        r[0]
        for r in await session.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'alert'")
        )
    }
    assert {"assignee_id", "triage_verdict", "closed_at", "updated_at"} <= cols
