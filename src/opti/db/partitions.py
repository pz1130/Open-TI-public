"""raw_item 月分区维护（设计文档 6.3：按月分区，过期整区删除）。"""

from __future__ import annotations

import re
from datetime import date

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_NAME = re.compile(r"raw_item_(\d{4})_(\d{2})")


def _month_start(d: date) -> date:
    return d.replace(day=1)


def _add_months(d: date, n: int) -> date:
    years, month0 = divmod(d.month - 1 + n, 12)
    return date(d.year + years, month0 + 1, 1)


def partition_name(month: date) -> str:
    return f"raw_item_{month:%Y_%m}"


async def ensure_raw_item_partitions(
    conn: AsyncConnection, today: date, months_ahead: int = 2
) -> list[str]:
    created: list[str] = []
    for i in range(months_ahead + 1):
        start = _add_months(_month_start(today), i)
        end = _add_months(start, 1)
        name = partition_name(start)
        if await conn.scalar(text("SELECT to_regclass(:n) IS NOT NULL"), {"n": name}):
            continue
        # 分区名与边界都由本函数生成，不含外部输入
        await conn.execute(
            text(
                f"CREATE TABLE {name} PARTITION OF raw_item "
                f"FOR VALUES FROM (TIMESTAMP WITH TIME ZONE '{start.isoformat()} 00:00:00+00') "
                f"TO (TIMESTAMP WITH TIME ZONE '{end.isoformat()} 00:00:00+00')"
            )
        )
        created.append(name)
    return created


async def drop_raw_item_partitions_before(
    conn: AsyncConnection, cutoff: date, *, dry_run: bool = False
) -> list[str]:
    rows = await conn.execute(
        text(
            "SELECT c.relname FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'raw_item'"
        )
    )
    dropped: list[str] = []
    for (name,) in rows.all():
        m = _NAME.fullmatch(str(name))
        if m and date(int(m[1]), int(m[2]), 1) < _month_start(cutoff):
            if not dry_run:
                await conn.execute(text(f'DROP TABLE "{name}"'))
            dropped.append(str(name))
    return sorted(dropped)
