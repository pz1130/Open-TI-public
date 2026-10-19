"""Alembic 环境：优先使用调用方传入的连接（opti.db.migrate.upgrade），否则自建异步引擎。"""

import asyncio

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from opti.db.models import Base

config = context.config
target_metadata = Base.metadata


def _include_name(name: str | None, type_: str, _parents: object) -> bool:
    # raw_item 的月分区由 opti.db.partitions 管理，不纳入自动比对
    return not (type_ == "table" and name is not None and name.startswith("raw_item_"))


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection, target_metadata=target_metadata, include_name=_include_name
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    engine = create_async_engine(config.get_main_option("sqlalchemy.url") or "")
    async with engine.begin() as conn:
        await conn.run_sync(do_run_migrations)
    await engine.dispose()


connection = config.attributes.get("connection")
if connection is not None:
    do_run_migrations(connection)
elif context.is_offline_mode():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(run_async_migrations())
