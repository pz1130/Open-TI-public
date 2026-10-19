"""Brave 新闻搜索（设计文档 4.1）：查询额度可控，默认待批准。"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import ClassVar

from opti.connectors.newsbase import OVERLAP, NewsConnector
from opti.core.feeds import parse_date, strip_html
from opti.core.urls import normalize_url
from opti.sdk.base import MissingCredential
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

API = "https://api.search.brave.com/res/v1/news/search"


class BraveNewsConnector(NewsConnector):
    id: ClassVar[str] = "brave_news"
    tier: ClassVar[Tier] = Tier.FREEMIUM

    def validate_config(self) -> None:
        if not self.ctx.secret("api_key"):
            raise MissingCredential("需要 api_key（OPTI_SECRET_BRAVE_NEWS_API_KEY）")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        headers = {
            "X-Subscription-Token": self.ctx.secret("api_key") or "",
            "Accept": "application/json",
        }
        emitted_urls: set[str] = set()
        for term in plan.terms[: int(self.config.get("max_queries", 5))]:
            q = f'"{term.value}"'
            key = "since:" + hashlib.sha256(q.encode()).hexdigest()[:16]
            since = parse_date(self.ctx.get_cursor(key))
            try:
                resp = await self.ctx.http().get(
                    str(self.config.get("api_base", API)),
                    params={
                        "q": q,
                        "count": "20",
                        "freshness": str(self.config.get("freshness", "pd")),
                    },
                    headers=headers,
                )
                doc = resp.json()
            except (HttpError, ValueError) as e:
                log.warning("Brave 搜索失败（%s），本轮停止：%s", q, e)
                return
            results = doc.get("results") if isinstance(doc, dict) else None
            newest = since
            for r in results if isinstance(results, list) else []:
                url = r.get("url") if isinstance(r, dict) else None
                if not isinstance(url, str):
                    continue
                canonical = normalize_url(url)
                if canonical is None or canonical in emitted_urls:
                    continue
                published = parse_date(r.get("page_age"))
                if since is not None and published is not None and published < since - OVERLAP:
                    continue
                emitted_urls.add(canonical)
                meta = r.get("meta_url") if isinstance(r.get("meta_url"), dict) else {}
                yield await self.document_item(
                    plan, item_id=canonical, url=url, title=strip_html(str(r.get("title") or "")),
                    summary=strip_html(str(r.get("description") or "")), language=None,
                    published=published, source_name=str(meta.get("hostname") or ""),
                    query=q, fetch=True,
                )  # fmt: skip
                if published is not None and (newest is None or published > newest):
                    newest = published
            if newest is not None and newest != since:
                self.ctx.set_cursor(key, newest.isoformat())
