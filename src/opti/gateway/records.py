"""采集网关写库：连接器运行的领取与结果、节点心跳。"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.cursors import save_cursors
from opti.db.models import CollectorNode, ConnectorRun

ACTIVE_RUN = ("dispatched", "running")


async def mark_run_leased(session: AsyncSession, run_id: int, node_id: str) -> None:
    await session.execute(
        update(ConnectorRun)
        .where(ConnectorRun.id == run_id, ConnectorRun.status == "dispatched")
        .values(status="running", node_id=node_id)
    )


async def finish_dispatched_run(
    session: AsyncSession, run_id: int, result: Mapping[str, Any], now: datetime
) -> bool:
    """写回游标并结束运行记录（节点先把本次运行的数据全部回传，才报告结果与游标）。

    已被判超时的运行不再写回游标：之后可能已下发新的运行，迟到的游标不能覆盖它；
    丢弃游标只会让下一次运行重复采集一段数据，处理器按 item_id 去重，不会重复告警。
    """
    run = await session.get(ConnectorRun, run_id, with_for_update=True)
    if run is None or run.status not in ACTIVE_RUN:
        return False
    cursors = result.get("cursors")
    if isinstance(cursors, dict) and cursors:
        values = {str(k): str(v) for k, v in cursors.items()}
        await save_cursors(session, run.connector_id, values, now)
    ok = result.get("status") == "ok"
    run.status = "ok" if ok else "error"
    run.items = int(result.get("items") or 0)
    run.errors = 0 if ok else 1
    run.message = str(result.get("message") or "")[:2000]
    run.ended_at = now
    await session.flush()
    return True


async def upsert_collector_node(
    session: AsyncSession,
    node_id: str,
    *,
    version: str,
    status: Mapping[str, Any],
    now: datetime,
) -> None:
    values = {"version": version, "status": dict(status), "last_seen": now}
    await session.execute(
        pg_insert(CollectorNode)
        .values(node_id=node_id, **values)
        .on_conflict_do_update(index_elements=[CollectorNode.node_id], set_=values)
    )
