"""urlscan.io 搜索（设计文档 4.5）：检索标题或域名中出现使用机构品牌的历史扫描。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.urlfeed import UrlFeedScanner
from opti.core.urls import normalize_url
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

SEARCH_URL = "https://urlscan.io/api/v1/search/"


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class UrlscanConnector(BaseConnector):
    id: ClassVar[str] = "urlscan"
    tier: ClassVar[Tier] = Tier.FREEMIUM

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)
        self._short_max = ctx.rules.domains.short_token_max_len

    def compile_queries(self, plan: QueryPlan) -> list[str]:
        out = [
            'page.title:"' + t.value.replace("\\", "\\\\") + '"'
            for t in plan.terms
            if '"' not in t.value
        ]
        authenticated = bool(self.ctx.secret("api_key"))
        for raw in plan.brand_tokens:
            token = raw.replace("-", "").lower()
            if len(token) > self._short_max:
                # Leading wildcards require authentication and a keyword RE
                # field. Parent domains are indexed for prefix-only searches.
                out.append(
                    f"page.domain.keyword:*{token}*" if authenticated else f"page.domain:{token}*"
                )
        return list(dict.fromkeys(out))

    async def _search(self, query: str) -> AsyncIterator[dict[str, Any]]:
        key = self.ctx.secret("api_key")
        headers = {"API-Key": key} if key else None
        lookback = str(self.config.get("lookback", "2d"))
        params = {
            "q": f"({query}) AND date:>now-{lookback}",
            "size": str(self.config.get("size", 100)),
        }
        for _ in range(int(self.config.get("max_pages", 3))):
            try:
                resp = await self.ctx.http().get(SEARCH_URL, params=params, headers=headers)
                data = resp.json()
            except (HttpError, ValueError) as e:
                self.ctx.logger().warning("urlscan 查询失败，跳过：%s（%s）", query, e)
                return
            results = (
                [r for r in (data.get("results") or []) if isinstance(r, dict)]
                if isinstance(data, dict)
                else []
            )
            for r in results:
                yield r
            if not (isinstance(data, dict) and data.get("has_more")) or not results:
                return
            sort = results[-1].get("sort")
            if not isinstance(sort, list) or not sort:
                return
            params = {**params, "search_after": ",".join(str(x) for x in sort)}

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        # 多个查询常返回同一条扫描：先汇总再统一扫描，同一 URL 只回传一次
        entries: dict[str, tuple[str, dict[str, Any]]] = {}
        for query in self.compile_queries(plan):
            async for r in self._search(query):
                page = _object(r.get("page"))
                task = _object(r.get("task"))
                verdicts = _object(r.get("verdicts"))
                # Search and full result APIs expose different nested verdicts.
                # Absence, strings, or a community-only verdict are not proof.
                confirmed = (
                    _object(verdicts.get("overall")).get("malicious") is True
                    or _object(verdicts.get("urlscan")).get("malicious") is True
                )
                raw = str(page.get("url") or task.get("url") or "")
                url = normalize_url(raw) or raw
                intel = {
                    "confirmed": confirmed,
                    "urlscan_uuid": task.get("uuid") or r.get("_id"),
                    "scan_time": task.get("time"),
                    "result_url": r.get("result"),
                }
                previous = entries.get(url)
                if previous is None:
                    entries[url] = (raw, intel)
                elif confirmed and not previous[1]["confirmed"]:
                    entries[url] = (previous[0], intel)
        for item in self._scanner.scan(entries.values(), plan):
            yield item
