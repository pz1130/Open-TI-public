"""迁移往返：在临时新建的数据库上升级、回退、再升级，不影响其他测试共用的库。"""

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, make_url, text
from sqlalchemy.ext.asyncio import create_async_engine

from opti.db.migrate import alembic_config, upgrade

pytestmark = pytest.mark.db


async def test_admin_business_settings_migration_round_trip(scratch_db: str) -> None:
    await upgrade(scratch_db)
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        checks = (
            await conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_config_revision_kind'"
                )
            )
        ).scalar_one()
        assert "identity" in checks and "operations" in checks
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0031")
    await engine.dispose()
    await upgrade(scratch_db)


async def test_watch_evidence_migration_round_trip(scratch_db: str) -> None:
    async def columns() -> dict[str, str]:
        engine = create_async_engine(scratch_db)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT column_name, is_nullable FROM information_schema.columns WHERE table_name = 'evidence' AND column_name IN ('finding_id', 'watch_observation_id')"
                    )
                )
                return dict(rows.all())
        finally:
            await engine.dispose()

    await upgrade(scratch_db)
    assert await columns() == {"finding_id": "YES", "watch_observation_id": "YES"}
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0029")
    await engine.dispose()
    assert await columns() == {"finding_id": "NO"}
    await upgrade(scratch_db)
    assert await columns() == {"finding_id": "YES", "watch_observation_id": "YES"}


def _downgrade(connection: Connection, cfg: Config, revision: str) -> None:
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, revision)


@pytest.fixture
async def scratch_db(pg_url: str) -> AsyncIterator[str]:
    name = f"opti_mig_{uuid4().hex[:12]}"
    admin = create_async_engine(pg_url, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield make_url(pg_url).set(database=name).render_as_string(hide_password=False)
    finally:
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


async def _objects(url: str) -> set[str]:
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT tablename FROM pg_tables WHERE tablename = 'dashboard_layout'"
                " UNION ALL SELECT indexname FROM pg_indexes"
                " WHERE indexname = 'uq_dashboard_layout_default'"
            )
        )
        names = {r[0] for r in rows}
    await engine.dispose()
    return names


async def test_dashboard_layout_migration_round_trip(scratch_db: str) -> None:
    both = {"dashboard_layout", "uq_dashboard_layout_default"}
    await upgrade(scratch_db)
    assert await _objects(scratch_db) == both
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0019")
    await engine.dispose()
    assert await _objects(scratch_db) == set()
    await upgrade(scratch_db)
    assert await _objects(scratch_db) == both


async def _llm_tables(url: str) -> set[str]:
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT tablename FROM pg_tables"
                " WHERE tablename IN ('llm_provider', 'llm_settings')"
            )
        )
        names = {r[0] for r in rows}
    await engine.dispose()
    return names


async def test_llm_tables_migration_round_trip(scratch_db: str) -> None:
    both = {"llm_provider", "llm_settings"}
    await upgrade(scratch_db)
    assert await _llm_tables(scratch_db) == both
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0020")
    await engine.dispose()
    assert await _llm_tables(scratch_db) == set()
    await upgrade(scratch_db)
    assert await _llm_tables(scratch_db) == both


async def _worker_columns(url: str) -> set[str]:
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'llm_settings'"
                " AND column_name IN ('worker_checked_at', 'worker_problem')"
            )
        )
        names = {r[0] for r in rows}
    await engine.dispose()
    return names


async def test_llm_worker_status_migration_round_trip(scratch_db: str) -> None:
    both = {"worker_checked_at", "worker_problem"}
    await upgrade(scratch_db)
    assert await _worker_columns(scratch_db) == both
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0021")
    await engine.dispose()
    assert await _worker_columns(scratch_db) == set()
    await upgrade(scratch_db)
    assert await _worker_columns(scratch_db) == both


async def _aggregation_objects(url: str) -> set[str]:
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'finding'"
                " AND column_name IN ('first_alerted_at', 'mttd_source', 'mttd_hours')"
                " UNION ALL SELECT indexname FROM pg_indexes WHERE indexname IN ("
                "'ix_finding_project_id_first_alerted_at', 'ix_finding_project_id_last_seen',"
                " 'ix_alert_project_id_created_at', 'ix_alert_project_id_status')"
            )
        )
        names = {r[0] for r in rows}
    await engine.dispose()
    return names


async def test_dashboard_aggregation_migration_round_trip(scratch_db: str) -> None:
    every = {
        "first_alerted_at", "mttd_source", "mttd_hours",
        "ix_finding_project_id_first_alerted_at", "ix_finding_project_id_last_seen",
        "ix_alert_project_id_created_at", "ix_alert_project_id_status",
    }  # fmt: skip
    await upgrade(scratch_db)
    assert await _aggregation_objects(scratch_db) == every
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0022")
    await engine.dispose()
    assert await _aggregation_objects(scratch_db) == set()
    await upgrade(scratch_db)
    assert await _aggregation_objects(scratch_db) == every


async def _connector_kinds(url: str) -> list[bool]:
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                " WHERE conname IN ('ck_config_revision_kind', 'ck_config_secret_kind')"
                " ORDER BY conname"
            )
        )
        defs = [r[0] for r in rows]
    await engine.dispose()
    return ["connectors" in d for d in defs]


async def test_connector_config_kind_migration_round_trip(scratch_db: str) -> None:
    await upgrade(scratch_db)
    assert await _connector_kinds(scratch_db) == [True, True]
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0026")
    await engine.dispose()
    assert await _connector_kinds(scratch_db) == [False, False]
    await upgrade(scratch_db)
    assert await _connector_kinds(scratch_db) == [True, True]


async def test_connector_config_kind_downgrade_refuses_with_data(scratch_db: str) -> None:
    await upgrade(scratch_db)
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO config_revision (kind, version, content, digest, created_by, created_at)"
                " VALUES ('connectors', 1, '', 'd', 'u', now())"
            )
        )
    with pytest.raises(RuntimeError, match="连接器"):
        async with engine.begin() as conn:
            await conn.run_sync(_downgrade, alembic_config(scratch_db), "0026")
    await engine.dispose()


async def test_certificate_monitor_migration_round_trip(scratch_db: str) -> None:
    async def tables() -> set[str]:
        engine = create_async_engine(scratch_db)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE tablename IN "
                        "('certificate_monitor', 'monitored_certificate')"
                    )
                )
                return {row[0] for row in rows}
        finally:
            await engine.dispose()

    await upgrade(scratch_db)
    assert await tables() == {"certificate_monitor", "monitored_certificate"}
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0027")
    await engine.dispose()
    assert await tables() == set()
    await upgrade(scratch_db)
    assert await tables() == {"certificate_monitor", "monitored_certificate"}


async def test_certificate_failing_since_migration_round_trip(scratch_db: str) -> None:
    async def columns() -> set[str]:
        engine = create_async_engine(scratch_db)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'monitored_certificate' AND column_name = 'failing_since'"
                    )
                )
                return {row[0] for row in rows}
        finally:
            await engine.dispose()

    await upgrade(scratch_db)
    assert await columns() == {"failing_since"}
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0028")
    await engine.dispose()
    assert await columns() == set()
    await upgrade(scratch_db)
    assert await columns() == {"failing_since"}


async def test_social_account_migration_round_trip(scratch_db: str) -> None:
    async def tables() -> set[str]:
        engine = create_async_engine(scratch_db)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE tablename IN "
                        "('protected_account', 'account_candidate')"
                    )
                )
                return {row[0] for row in rows}
        finally:
            await engine.dispose()

    await upgrade(scratch_db)
    assert await tables() == {"protected_account", "account_candidate"}
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0030")
    await engine.dispose()
    assert await tables() == set()
    await upgrade(scratch_db)
    assert await tables() == {"protected_account", "account_candidate"}


async def test_certificate_approval_and_ignore_migration_preserves_history(scratch_db: str) -> None:
    await upgrade(scratch_db)
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0032")
        await conn.execute(
            text("INSERT INTO project (id, name, authorization_ref) VALUES ('p', 'P', 'test')")
        )
        await conn.execute(
            text(
                "INSERT INTO entity (id, type, value, first_seen, last_seen) VALUES (1, 'tls_endpoint', 'example.com@1', now(), now())"
            )
        )
        await conn.execute(
            text("""INSERT INTO finding (id, project_id, entity_id, category, score, severity, first_seen, last_seen, match)
            VALUES (1, 'p', 1, 'certificate_expiry', 70, 'high', now(), now(), '{"certificate_alert_key":"old"}')""")
        )
        await conn.execute(
            text(
                "INSERT INTO alert (id, project_id, severity, created_at) VALUES (1, 'p', 'high', now())"
            )
        )
        await conn.execute(text("INSERT INTO alert_finding (alert_id, finding_id) VALUES (1, 1)"))
        await conn.execute(
            text(
                "INSERT INTO certificate_monitor (id, project_id, root_domain, created_at, next_check_at) VALUES (1, 'p', 'example.com', now(), now())"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO monitored_certificate (id, monitor_id, domain) VALUES (1, 1, 'example.com')"
            )
        )
    await engine.dispose()
    await upgrade(scratch_db)
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        alert = (
            await conn.execute(
                text(
                    "SELECT status, closed_at, ignored_at, ignored_fingerprint FROM alert WHERE id = 1"
                )
            )
        ).one()
        assert (
            alert.status == "closed"
            and alert.closed_at
            and alert.ignored_at is None
            and alert.ignored_fingerprint == {}
        )
        host = (
            await conn.execute(
                text(
                    "SELECT approved_at, approved_by, warn_days FROM monitored_certificate WHERE id = 1"
                )
            )
        ).one()
        assert tuple(host) == (None, None, None)
        assert (
            await conn.execute(text("SELECT match FROM finding WHERE id = 1"))
        ).scalar_one() == {}
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0032")
    await engine.dispose()
    await upgrade(scratch_db)


async def test_llm_code_enabled_migration_round_trip(scratch_db: str) -> None:
    await upgrade(scratch_db)
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0036")
        await conn.execute(
            text(
                "INSERT INTO llm_settings (id, enabled, gray_zone_low, gray_zone_high, max_per_run,"
                " max_attempts, max_wait_minutes, summary_language, updated_at)"
                " VALUES (1, true, 30, 70, 20, 3, 30, 'Chinese', now())"
            )
        )
    await engine.dispose()
    await upgrade(scratch_db)
    engine = create_async_engine(scratch_db)
    async with engine.begin() as conn:
        flag = (await conn.execute(text("SELECT code_enabled FROM llm_settings"))).scalar_one()
        assert flag is False  # 升级后默认关闭
        await conn.run_sync(_downgrade, alembic_config(scratch_db), "0036")
        cols = await conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_name = 'llm_settings' AND column_name = 'code_enabled'"
            )
        )
        assert cols.all() == []
    await engine.dispose()
    await upgrade(scratch_db)
