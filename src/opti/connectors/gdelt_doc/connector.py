"""GDELT DOC 2.0（设计文档 4.1）：全球新闻关键词检索。GDELT 按英文译文检索，只发送 ASCII 短语。

请每 5 秒最多 1 次请求；返回的只有标题与链接，正文在采集节点上抓取（只用于匹配）。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from opti.connectors.newsbase import OVERLAP, NewsConnector
from opti.core.feeds import parse_date, strip_html
from opti.core.urls import normalize_url
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://api.gdeltproject.org/api/v2/doc/doc"
BATCH = 5
LOOKBACK = timedelta(days=1)
LANGUAGES = {
    "english": "en", "chinese": "zh", "portuguese": "pt", "russian": "ru", "spanish": "es", "french": "fr",
    "arabic": "ar", "german": "de", "japanese": "ja", "hindi": "hi", "italian": "it", "korean": "ko",
}  # fmt: skip


def _gdelt_time(value: Any) -> datetime | None:
    try:
        return datetime.strptime(str(value), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


class GdeltDocConnector(NewsConnector):
    id: ClassVar[str] = "gdelt_doc"
    tier: ClassVar[Tier] = Tier.FREE

    def compile_queries(self, plan: QueryPlan) -> list[str]:
        terms = [t.value for t in plan.terms if t.value.isascii() and len(t.value) >= 3]
        out = []
        for i in range(0, len(terms), BATCH):
            chunk = terms[i : i + BATCH]
            out.append(
                f'"{chunk[0]}"'
                if len(chunk) == 1
                else "(" + " OR ".join(f'"{t}"' for t in chunk) + ")"
            )
        return out

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        since = parse_date(self.ctx.get_cursor("since"))
        now = utcnow()
        start = since - OVERLAP if since is not None else now - LOOKBACK
        newest = since
        complete = True
        emitted_urls: set[str] = set()
        for q in self.compile_queries(plan)[: int(self.config.get("max_queries", 10))]:
            try:
                resp = await self.ctx.http().get(
                    str(self.config.get("api_base", API)),
                    params={
                        "query": q, "mode": "ArtList", "format": "json", "maxrecords": "250", "sort": "DateDesc",
                        "startdatetime": start.strftime("%Y%m%d%H%M%S"), "enddatetime": now.strftime("%Y%m%d%H%M%S"),
                    },
                )  # fmt: skip
                doc = resp.json()
            except (HttpError, ValueError) as e:  # 限流时 GDELT 返回纯文本说明
                log.warning("GDELT 查询失败：%s", e)
                complete = False
                break
            articles = doc.get("articles") if isinstance(doc, dict) else None
            for a in articles if isinstance(articles, list) else []:
                url = a.get("url") if isinstance(a, dict) else None
                if not isinstance(url, str):
                    continue
                canonical = normalize_url(url)
                if canonical is None or canonical in emitted_urls:
                    continue
                emitted_urls.add(canonical)
                seen = _gdelt_time(a.get("seendate"))
                yield await self.document_item(
                    plan, item_id=canonical, url=url, title=strip_html(str(a.get("title") or "")), summary="",
                    language=LANGUAGES.get(str(a.get("language") or "").lower()), published=seen,
                    source_name=str(a.get("domain") or ""), query=q, fetch=True,
                )  # fmt: skip
                if seen is not None and (newest is None or seen > newest):
                    newest = seen
        if complete and newest is not None and newest != since:
            self.ctx.set_cursor("since", newest.isoformat())
