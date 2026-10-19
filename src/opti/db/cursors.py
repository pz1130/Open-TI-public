"""PostgreSQL 游标存储：连接器接口是同步的，因此在运行开始时整体加载、结束时写回（至少一次语义）。"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import ConnectorCursor
from opti.sdk.context import MemoryCursorStore


class PgCursorStore(MemoryCursorStore):
    def __init__(self) -> None:
        super().__init__()
        self._dirty: set[tuple[str, str]] = set()

    def set(self, connector_id: str, key: str, value: str) -> None:
        super().set(connector_id, key, value)
        self._dirty.add((connector_id, key))

    async def load(self, session: AsyncSession, connector_id: str) -> None:
        rows = await session.execute(
            select(ConnectorCursor.key, ConnectorCursor.value).where(
                ConnectorCursor.connector_id == connector_id
            )
        )
        for key, value in rows.all():
            super().set(connector_id, key, value)

    async def flush(self, session: AsyncSession, now: datetime) -> int:
        by_connector: dict[str, dict[str, str]] = {}
        for connector_id, key in self._dirty:
            value = self.get(connector_id, key)
            assert value is not None
            by_connector.setdefault(connector_id, {})[key] = value
        count = 0
        for connector_id, values in sorted(by_connector.items()):
            count += await save_cursors(session, connector_id, values, now)
        self._dirty.clear()
        return count


async def save_cursors(
    session: AsyncSession, connector_id: str, values: Mapping[str, str], now: datetime
) -> int:
    for key, value in sorted(values.items()):
        stmt = (
            pg_insert(ConnectorCursor)
            .values(connector_id=connector_id, key=key, value=value, updated_at=now)
            .on_conflict_do_update(
                index_elements=[ConnectorCursor.connector_id, ConnectorCursor.key],
                set_={"value": value, "updated_at": now},
            )
        )
        await session.execute(stmt)
    return len(values)
