"""KEV 条目入库与补比对（设计文档 4.8）。"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.kev import Kev, normalize_name
from opti.db.models import KevEntry

if TYPE_CHECKING:
    from opti.pipeline.processor import Processor


async def upsert_entry(session: AsyncSession, kev: Kev, now: datetime) -> KevEntry:
    values = {
        "vendor": kev.vendor, "product": kev.product, "name": kev.name, "description": kev.description,
        "required_action": kev.required_action, "date_added": kev.date_added, "due_date": kev.due_date,
        "ransomware": kev.ransomware, "notes": kev.notes, "cwes": list(kev.cwes),
    }  # fmt: skip
    stmt = (
        pg_insert(KevEntry)
        .values(cve_id=kev.cve, first_seen=now, last_seen=now, **values)
        .on_conflict_do_update(index_elements=["cve_id"], set_={**values, "last_seen": now})
        .returning(KevEntry)
    )
    return (await session.scalars(stmt, execution_options={"populate_existing": True})).one()


def public_entry(row: KevEntry) -> dict[str, Any]:
    return {
        "cve": row.cve_id, "vendor": row.vendor, "product": row.product, "name": row.name,
        "description": row.description, "required_action": row.required_action,
        "date_added": row.date_added.isoformat(), "due_date": row.due_date.isoformat() if row.due_date else None,
        "ransomware": row.ransomware, "notes": row.notes, "cwes": list(row.cwes),
    }  # fmt: skip


async def rematch(session: AsyncSession, processor: Processor, *, now: datetime) -> list[int]:
    """软件清单变化后，把全部 KEV 条目（约 1500 条）重新比对。返回新告警 ID。"""
    alerts: list[int] = []
    for row in (await session.scalars(select(KevEntry).order_by(KevEntry.id))).all():
        alerts += await processor.rematch_kev(session, row, now)
    return alerts


async def products(session: AsyncSession, vendor: str | None = None) -> list[tuple[str, str, int]]:
    """列出 KEV 中的厂商与产品名（填写软件清单时对照准确写法）。"""
    rows = (
        await session.execute(
            select(KevEntry.vendor, KevEntry.product, func.count())
            .group_by(KevEntry.vendor, KevEntry.product)
            .order_by(KevEntry.vendor, KevEntry.product)
        )
    ).all()
    want = normalize_name(vendor) if vendor else None
    return [(v, p, int(n)) for v, p, n in rows if want is None or normalize_name(v) == want]
