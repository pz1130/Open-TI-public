"""OpenPhish 社区列表（设计文档 4.5）。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.urlfeed import UrlFeedScanner
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

FEED_URL = "https://openphish.com/feed.txt"


class OpenPhishConnector(BaseConnector):
    id: ClassVar[str] = "openphish"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        try:
            resp = await self.ctx.http().get(str(self.config.get("feed_url", FEED_URL)))
        except HttpError as e:
            self.ctx.logger().warning("OpenPhish 列表下载失败：%s", e)
            return
        lines = (
            line for line in resp.text.splitlines() if line.strip() and not line.startswith("#")
        )
        for item in self._scanner.scan(((u, {"confirmed": True}) for u in lines), plan):
            yield item
        self.ctx.logger().info("OpenPhish：%s", self._scanner.stats)
