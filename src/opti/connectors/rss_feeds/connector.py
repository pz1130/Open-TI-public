"""机构配置的 RSS / Atom 订阅（设计文档 4.1）：媒体、监管机构、CERT 公告。

先用标题与摘要粗筛（任一匹配词出现），只为可能相关的条目抓取正文；关键订阅源可设 fetch_all 全部抓取。
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import ClassVar
from urllib.parse import urlsplit

from opti.connectors.newsbase import OVERLAP, NewsConnector
from opti.core.feeds import MAX_FEED_BYTES, FeedError, parse_date, parse_feed
from opti.core.text_match import TextMatcher
from opti.sdk.models import QueryPlan, RawItem, Tier
from opti.sdk.safefetch import FetchError, SafeFetcher, ascii_url


class RssFeedsConnector(NewsConnector):
    id: ClassVar[str] = "rss_feeds"
    tier: ClassVar[Tier] = Tier.FREE

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        matcher = TextMatcher(self.ctx.rules)
        for feed in self.config.get("feeds") or []:
            if not isinstance(feed, dict):
                log.warning("跳过格式不合法的订阅源配置")
                continue
            url = str(feed.get("url") or "")
            if ascii_url(url) is None:
                log.warning("跳过不是 http(s) 的订阅源：%s", url)
                continue
            name = str(feed.get("name") or urlsplit(url).hostname or url)
            fetch_all = bool(feed.get("fetch_all", False))
            key = "since:" + hashlib.sha256(url.encode()).hexdigest()[:16]
            since = parse_date(self.ctx.get_cursor(key))
            try:
                fetcher = SafeFetcher(
                    self.ctx.http(),
                    resolve=self.resolve,
                    max_body_bytes=MAX_FEED_BYTES,
                    timeout=float(self.config.get("feed_timeout", 15.0)),
                    truncate_body=False,
                )
                response, _, _ = await fetcher.open(url)
                items = parse_feed(response.content)
            except (FetchError, FeedError) as e:
                log.warning("读取订阅源 %s 失败：%s", name, e)
                continue
            newest = since
            for it in items:
                if not (it.guid or it.link or it.title):
                    continue
                if (
                    since is not None
                    and it.published is not None
                    and it.published < since - OVERLAP
                ):
                    continue
                candidate = matcher.may_match(f"{it.title}\n{it.summary}")
                if candidate or fetch_all:
                    link = ascii_url(it.link) if it.link else None
                    yield await self.document_item(
                        plan, item_id=f"{url}#{it.guid}", url=link, title=it.title, summary=it.summary,
                        language=feed.get("language"), published=it.published, source_name=name, query=None,
                        fetch=True,
                    )  # fmt: skip
                if it.published is not None and (newest is None or it.published > newest):
                    newest = it.published
            if newest is not None and newest != since:
                self.ctx.set_cursor(key, newest.isoformat())
