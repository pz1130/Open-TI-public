"""Google News RSS 搜索（设计文档 4.1）：非正式公开接口，稳定性与条款需核实，低频使用；默认待法务批准。

条目链接是 Google 的跳转页，不抓取正文；用标题与摘要匹配。
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import AsyncIterator, Sequence
from typing import Any, ClassVar

from opti.connectors.newsbase import OVERLAP, NewsConnector
from opti.core.feeds import MAX_FEED_BYTES, FeedError, parse_date, parse_feed
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

API = "https://news.google.com/rss/search"
DEFAULT_EDITIONS: tuple[dict[str, str], ...] = (
    {"hl": "en-US", "gl": "US", "ceid": "US:en"},
    {"hl": "zh-CN", "gl": "CN", "ceid": "CN:zh-Hans"},
)
_CJK = re.compile(r"[㐀-鿿豈-﫿]")


def edition_queries(
    plan: QueryPlan, editions: Sequence[dict[str, str]], limit: int
) -> list[tuple[dict[str, str], str]]:
    """中文版本只用含中文字符的词，其他版本只用不含中文的词。"""
    out: list[tuple[dict[str, str], str]] = []
    for ed in editions:
        zh = ed["hl"].lower().startswith("zh")
        out += [(ed, f'"{t.value}"') for t in plan.terms if bool(_CJK.search(t.value)) == zh]
    return out[:limit]


class GoogleNewsConnector(NewsConnector):
    id: ClassVar[str] = "google_news"
    tier: ClassVar[Tier] = Tier.FREE

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        editions: list[dict[str, Any]] = list(self.config.get("editions") or DEFAULT_EDITIONS)
        for ed, q in edition_queries(plan, editions, int(self.config.get("max_queries", 10))):
            key = "since:" + hashlib.sha256(f"{ed['hl']}|{q}".encode()).hexdigest()[:16]
            since = parse_date(self.ctx.get_cursor(key))
            try:
                resp = await self.ctx.http().get(
                    str(self.config.get("api_base", API)),
                    params={"q": q, "hl": ed["hl"], "gl": ed["gl"], "ceid": ed["ceid"]},
                    max_body_bytes=MAX_FEED_BYTES,
                )
                items = parse_feed(resp.content)
            except (HttpError, FeedError) as e:
                log.warning("Google News 搜索失败（%s %s）：%s", ed["hl"], q, e)
                continue
            newest = since
            for it in items:
                if (
                    since is not None
                    and it.published is not None
                    and it.published < since - OVERLAP
                ):
                    continue
                yield await self.document_item(
                    plan, item_id=it.guid or it.link, url=it.link or None, title=it.title, summary=it.summary,
                    language=ed["hl"].split("-")[0].lower(), published=it.published,
                    source_name=it.source_name or "Google News", query=q, fetch=False,
                )  # fmt: skip
                if it.published is not None and (newest is None or it.published > newest):
                    newest = it.published
            if newest is not None and newest != since:
                self.ctx.set_cursor(key, newest.isoformat())
