"""ThreatFox 最近 48 小时的 IOC（abuse.ch，设计文档 4.8）。

只处理域名与 URL 两类；含本机构品牌的条目按情报确认的仿冒域名 / 钓鱼 URL 进入既有 URL 流程（S2-A）。只读导出文件，不访问 IOC。
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any, ClassVar

from opti.connectors.urlfeed import UrlFeedScanner
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

API = "https://threatfox.abuse.ch/export/json/recent/"
KINDS = frozenset({"domain", "url"})
MAX_EXPORT_BYTES = 50 * 1024 * 1024


def threatfox_records(doc: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """兼容两种格式：导出文件 `{ID: [记录]}` 与查询接口 `{"query_status": "ok", "data": [记录]}`。"""
    if not isinstance(doc, dict):
        return
    if isinstance(doc.get("data"), list):
        for r in doc["data"]:
            if isinstance(r, dict):
                yield str(r.get("id") or ""), r
        return
    for key, records in doc.items():
        if isinstance(records, list):
            for r in records:
                if isinstance(r, dict):
                    yield str(key), r


def _tags(value: Any) -> list[str]:
    items = value.split(",") if isinstance(value, str) else value if isinstance(value, list) else []
    return [t.strip()[:50] for t in items if isinstance(t, str) and t.strip()][:20]


def _confidence(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class ThreatFoxConnector(BaseConnector):
    id: ClassVar[str] = "threatfox"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)

    def validate_config(self) -> None:
        if not self.ctx.secret("auth_key"):
            raise MissingCredential("需要 abuse.ch Auth-Key（OPTI_SECRET_THREATFOX_AUTH_KEY）")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        log = self.ctx.logger()
        try:
            resp = await self.ctx.http().get(
                str(self.config.get("api_base", API)),
                headers={"Auth-Key": self.ctx.secret("auth_key") or ""},
                max_body_bytes=MAX_EXPORT_BYTES,
            )
            doc = resp.json()
        except (HttpError, ValueError) as e:
            log.warning("ThreatFox 导出读取失败：%s", e)
            return
        if (
            isinstance(doc, dict)
            and isinstance(doc.get("query_status"), str)
            and doc["query_status"] != "ok"
        ):
            log.warning("ThreatFox 返回状态：%s", doc["query_status"])
            return
        min_confidence = int(self.config.get("min_confidence", 50))
        entries: list[tuple[str, dict[str, Any]]] = []
        for rid, r in threatfox_records(doc):
            kind = r.get("ioc_type")
            value = str(r.get("ioc_value") or r.get("ioc") or "").strip()
            if kind not in KINDS or not value:
                continue
            confidence = _confidence(r.get("confidence_level"))
            entries.append((
                value if kind == "url" else f"http://{value}/",
                {
                    "confirmed": confidence >= min_confidence, "threat": r.get("threat_type"),
                    "malware": r.get("malware_printable"), "confidence": confidence, "tags": _tags(r.get("tags")),
                    "first_seen": r.get("first_seen_utc") or r.get("first_seen"), "threatfox_id": rid,
                },
            ))  # fmt: skip
        for item in self._scanner.scan(entries, plan):
            yield item
        log.info("ThreatFox：%s", self._scanner.stats)
