"""Phishing.Database 每日新增列表（设计文档 4.5）。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.urlfeed import UrlFeedScanner
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

BASE = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master"
LINKS_URL = f"{BASE}/phishing-links-NEW-today.txt"
DOMAINS_URL = f"{BASE}/phishing-domains-NEW-today.txt"
LISTS = {"links": LINKS_URL, "domains": DOMAINS_URL}


class PhishingDbConnector(BaseConnector):
    id: ClassVar[str] = "phishing_db"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        for name in self.config.get("lists", ["links", "domains"]):
            try:
                resp = await self.ctx.http().get(LISTS[str(name)])
            except HttpError as e:
                self.ctx.logger().warning("Phishing.Database %s 下载失败，跳过：%s", name, e)
                continue
            lines = (x.strip() for x in resp.text.splitlines())
            entries = (
                (line if name == "links" else f"http://{line}/", {"confirmed": True, "list": name})
                for line in lines
                if line and not line.startswith("#")
            )
            for item in self._scanner.scan(entries, plan):
                yield item
        self.ctx.logger().info("Phishing.Database：%s", self._scanner.stats)
