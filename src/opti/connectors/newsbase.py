"""新闻类连接器的公共部分（设计文档 4.1）：在采集节点上安全抓取正文（只用于匹配，平台不存全文），产出 document 载荷。"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from opti.connectors.articles import fetch_article
from opti.core.documents import document_payload
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, utcnow
from opti.sdk.safefetch import Resolver, SafeFetcher

OVERLAP = timedelta(hours=1)


def _source_id(value: str) -> str:
    if len(value) <= 500:
        return value
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"{value[:400]}#{digest}"


class NewsConnector(BaseConnector):
    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self.resolve: Resolver | None = None  # 测试中替换为假解析
        self._fetcher: SafeFetcher | None = None
        self._articles_left = int(config.get("max_articles", 50))

    def fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            self._fetcher = SafeFetcher(
                self.ctx.http(),
                resolve=self.resolve,
                timeout=float(self.config.get("article_timeout", 10.0)),
            )
        return self._fetcher

    async def document_item(
        self,
        plan: QueryPlan,
        *,
        item_id: str,
        url: str | None,
        title: str,
        summary: str,
        language: str | None,
        published: datetime | None,
        source_name: str,
        query: str | None,
        fetch: bool,
    ) -> RawItem:
        text = ""
        if fetch and url and self._articles_left > 0:
            self._articles_left -= 1
            article = await fetch_article(self.fetcher(), url)
            if article is not None:
                text = article.text
                title = title or article.title
                language = language or article.language
        return RawItem(
            connector_id=self.id,
            source_item_id=_source_id(item_id),
            fetched_at=utcnow(),
            url=url,
            payload=document_payload(
                url=url,
                title=title,
                summary=summary,
                text=text,
                language=language,
                published_at=published,
                source_name=source_name,
                query=query,
            ),
            project_ids=plan.project_ids,
        )
