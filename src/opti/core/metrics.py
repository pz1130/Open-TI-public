"""运营指标（设计文档 1.4、14）：MTTD 的来源事件时间与汇总。纯逻辑。

CT 来源以证书进入 CT 日志的时间为起点（certstream 的 seen、crt.sh 的 entry_timestamp；缺失时用 not_before），
NRD / dnstwist 以 RDAP 注册时间为起点（通常只精确到日，结果偏大）。
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

CT_SOURCES = frozenset({"certstream", "crtsh"})
NRD_SOURCES = frozenset({"nrd", "dnstwist"})
TARGET_HOURS = {"ct": 1.0, "nrd": 24.0}  # 设计文档 1.4 的 MVP 目标


def target_hours() -> dict[str, float]:
    from opti.core import policy

    return {"ct": policy.current().risk.mttd_ct_hours, "nrd": policy.current().risk.mttd_nrd_hours}


def parse_time(value: Any) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if value <= 0:
            return None
        try:
            return datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return None


def ct_event_time(connector_id: str, payload: Mapping[str, Any]) -> datetime | None:
    if connector_id == "certstream":
        cert = payload.get("cert")
        if not isinstance(cert, Mapping):
            return None
        return parse_time(cert.get("seen")) or parse_time(cert.get("not_before"))
    if connector_id == "crtsh":
        return parse_time(payload.get("entry_timestamp")) or parse_time(payload.get("not_before"))
    return None


def registration_time(enrichment: Mapping[str, Any]) -> datetime | None:
    entry = enrichment.get("rdap")
    data = entry.get("data") if isinstance(entry, Mapping) else None
    return parse_time(data.get("registration")) if isinstance(data, Mapping) else None


def source_group(connector_id: str) -> str | None:
    if connector_id in CT_SOURCES:
        return "ct"
    if connector_id in NRD_SOURCES:
        return "nrd"
    return None


def median(values: Sequence[float]) -> float | None:
    return round(float(statistics.median(values)), 2) if values else None


@dataclass(frozen=True)
class MttdStat:
    source: str
    count: int
    median_hours: float | None
    within_target: float | None  # 达标比例（0–1）
    target_hours: float


def summarize(samples: Mapping[str, Sequence[float]]) -> list[MttdStat]:
    out = []
    for source, target in target_hours().items():
        values = list(samples.get(source) or [])
        within = round(sum(v < target for v in values) / len(values), 3) if values else None
        out.append(MttdStat(source, len(values), median(values), within, target))
    return out
