"""下架统计（设计文档 12.1）：MTTR（发现到下架）与各投诉对象的响应时长，作为是否采购付费下架服务的依据。"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from statistics import median
from typing import Any

REMOVED = ("removed", "reappeared")


@dataclass(frozen=True)
class StatRow:
    state: str
    target_name: str
    target_kind: str
    submitted_at: datetime | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    first_seen: datetime


def _hours(start: datetime, end: datetime) -> float:
    return (end - start).total_seconds() / 3600


def _median(values: list[float]) -> float | None:
    return round(median(values), 1) if values else None


def compute(rows: Sequence[StatRow]) -> dict[str, Any]:
    mttr = [
        _hours(r.first_seen, r.resolved_at) for r in rows if r.state in REMOVED and r.resolved_at
    ]
    groups: dict[tuple[str, str], list[StatRow]] = defaultdict(list)
    for r in rows:
        groups[(r.target_kind, r.target_name)].append(r)
    targets = []
    for (kind, name), items in sorted(groups.items()):
        # 响应时长：提交到对方第一次有回应（受理、下架或拒绝）
        response = [
            _hours(r.submitted_at, r.acknowledged_at or r.resolved_at)  # type: ignore[arg-type]
            for r in items
            if r.submitted_at and (r.acknowledged_at or r.resolved_at)
        ]
        targets.append(
            {
                "name": name, "kind": kind, "total": len(items),
                "removed": sum(r.state in REMOVED for r in items),
                "rejected": sum(r.state == "rejected" for r in items),
                "median_response_hours": _median(response),
            }
        )  # fmt: skip
    return {
        "by_state": dict(Counter(r.state for r in rows)),
        "mttr_hours": _median(mttr),
        "targets": targets,
    }
