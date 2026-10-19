"""在异步程序中执行 Alembic 迁移（Alembic 官方 cookbook 的"共享连接"写法）。"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from opti.db.partitions import ensure_raw_item_partitions

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    # ConfigParser 会把 % 当作插值符号
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def _run_upgrade(connection: Connection, cfg: Config, revision: str) -> None:
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


async def upgrade(url: str, revision: str = "head") -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(_run_upgrade, alembic_config(url), revision)
            await ensure_raw_item_partitions(conn, datetime.now(UTC).date())
    finally:
        await engine.dispose()
