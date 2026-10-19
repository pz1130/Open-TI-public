"""AlienVault OTX 情报包检索（设计文档 4.8）：搜索提及本机构的 Pulse，产出 kind 为 intel 的文档载荷。

只发送允许外部检索的短语；只接收公开（TLP white / clear / green）的情报包；不抓取页面。
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import AsyncIterator, Mapping
from datetime import timedelta
from typing import Any, ClassVar

from opti.core.documents import document_payload
from opti.core.feeds import parse_date
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://otx.alienvault.com/api/v1/search/pulses"
PULSE_URL = "https://otx.alienvault.com/pulse/{}"
PUBLIC_TLP = frozenset({"white", "clear", "green"})
OVERLAP = timedelta(hours=1)
_PULSE_ID = re.compile(r"^[0-9a-f]{24}$")
_LISTS = (
    ("Tags", "tags"), ("Industries", "industries"), ("Targeted countries", "targeted_countries"),
    ("Malware", "malware_families"), ("References", "references"),
)  # fmt: skip


def _names(value: Any) -> list[str]:
    """字符串列表，或 {"display_name" / "name": ...} 列表 → 名称列表。"""
    out: list[str] = []
    for v in value if isinstance(value, list) else []:
        name = (
            v
            if isinstance(v, str)
            else (v.get("display_name") or v.get("name"))
            if isinstance(v, dict)
            else None
        )
        if isinstance(name, str) and name.strip():
            out.append(name.strip()[:200])
    return out[:30]


def pulse_text(p: Mapping[str, Any]) -> str:
    """匹配用的正文：描述、对手、标签、行业、目标国家、恶意软件家族与参考链接。只在传输中出现，不入库。"""
    parts = [str(p.get("description") or "").strip()]
    adversary = p.get("adversary")
    if isinstance(adversary, str) and adversary.strip():
        parts.append(f"Adversary: {adversary.strip()[:200]}")
    for label, key in _LISTS:
        names = _names(p.get(key))
        if names:
            parts.append(f"{label}: {', '.join(names)}")
    return "\n".join(x for x in parts if x)


class OtxConnector(BaseConnector):
    id: ClassVar[str] = "otx"
    tier: ClassVar[Tier] = Tier.FREE

    def validate_config(self) -> None:
        if not self.ctx.secret("api_key"):
            raise MissingCredential("需要 OTX API Key（OPTI_SECRET_OTX_API_KEY）")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        headers = {"X-OTX-API-KEY": self.ctx.secret("api_key") or "", "Accept": "application/json"}
        for term in plan.terms[: int(self.config.get("max_queries", 10))]:
            q = f'"{term.value}"'
            key = "since:" + hashlib.sha256(term.value.encode()).hexdigest()[:16]
            since = parse_date(self.ctx.get_cursor(key))
            try:
                resp = await self.ctx.http().get(
                    str(self.config.get("api_base", API)),
                    params={"q": q, "sort": "-modified", "limit": "20", "page": "1"},
                    headers=headers,
                )
                doc = resp.json()
            except (HttpError, ValueError) as e:
                log.warning("OTX 搜索失败（%s），本轮停止：%s", q, e)
                return
            results = doc.get("results") if isinstance(doc, dict) else None
            newest = since
            for p in results if isinstance(results, list) else []:
                if not isinstance(p, dict):
                    continue
                pid = str(p.get("id") or "")
                tlp = str(p.get("tlp") or p.get("TLP") or "white").lower()
                if not _PULSE_ID.fullmatch(pid) or tlp not in PUBLIC_TLP:
                    continue
                modified = parse_date(p.get("modified")) or parse_date(p.get("created"))
                if since is not None and modified is not None and modified < since - OVERLAP:
                    continue
                author = str(p.get("author_name") or "").strip()[:100]
                url = PULSE_URL.format(pid)
                payload = document_payload(
                    url=url, title=str(p.get("name") or "")[:500], summary=str(p.get("description") or "")[:2000],
                    text=pulse_text(p), published_at=modified, query=q, kind="intel",
                    source_name=f"AlienVault OTX · {author}" if author else "AlienVault OTX",
                )  # fmt: skip
                yield RawItem(
                    connector_id=self.id,
                    source_item_id=f"{pid}#{modified.isoformat() if modified else ''}",  # 情报包更新后重新评分
                    fetched_at=utcnow(),
                    url=url,
                    payload=payload,
                    project_ids=plan.project_ids,
                )
                if modified is not None and (newest is None or modified > newest):
                    newest = modified
            if newest is not None and newest != since:
                self.ctx.set_cursor(key, newest.isoformat())
