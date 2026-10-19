"""连接器 SDK 的数据模型（设计文档 5.3）。"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal


class Tier(StrEnum):
    FREE = "free"
    FREEMIUM = "freemium"
    PAID = "paid"


@dataclass(frozen=True)
class SearchTerm:
    """与数据源无关的检索词；由连接器的 compile_queries() 编译成具体语法。"""

    value: str
    kind: Literal["phrase"]
    lang: str | None = None


@dataclass(frozen=True)
class QueryPlan:
    project_ids: tuple[str, ...]
    terms: tuple[SearchTerm, ...] = ()
    domains: tuple[str, ...] = ()  # 官方域名
    brand_tokens: tuple[str, ...] = ()  # 域名品牌词
    # 受限品牌词与其必须组合的词缀：((品牌词, (词缀, ...)), ...)
    restricted_tokens: tuple[tuple[str, tuple[str, ...]], ...] = ()
    languages: tuple[str, ...] = ()
    since: datetime | None = None


@dataclass(frozen=True)
class RawItem:
    connector_id: str
    source_item_id: str  # 数据源内部 ID，或规范化后的域名/URL
    fetched_at: datetime
    url: str | None
    payload: dict[str, Any]
    content_type: str = "application/json"
    project_ids: tuple[str, ...] = ()

    @property
    def item_id(self) -> str:
        """确定性 ID，重放不会产生重复（设计文档 3.3）。"""
        key = f"{self.connector_id}\x00{self.source_item_id}".encode()
        return hashlib.sha256(key).hexdigest()


@dataclass(frozen=True)
class HealthStatus:
    ok: bool
    message: str = ""
    quota_remaining: int | None = None


def utcnow() -> datetime:
    return datetime.now(UTC)


def raw_item_to_dict(item: RawItem) -> dict[str, Any]:
    """序列化为可经任务队列传输的 JSON 结构。"""
    return {
        "connector_id": item.connector_id,
        "source_item_id": item.source_item_id,
        "fetched_at": item.fetched_at.isoformat(),
        "url": item.url,
        "payload": item.payload,
        "content_type": item.content_type,
        "project_ids": list(item.project_ids),
    }


def raw_item_from_dict(d: Mapping[str, Any]) -> RawItem:
    return RawItem(
        connector_id=str(d["connector_id"]),
        source_item_id=str(d["source_item_id"]),
        fetched_at=datetime.fromisoformat(str(d["fetched_at"])),
        url=d.get("url"),
        payload=dict(d.get("payload") or {}),
        content_type=str(d.get("content_type") or "application/json"),
        project_ids=tuple(str(p) for p in d.get("project_ids") or ()),
    )
