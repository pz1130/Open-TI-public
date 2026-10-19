"""新注册域名（NRD）批处理（设计文档 4.5）：下载每日列表 → 预过滤 → 匹配。"""

from __future__ import annotations

import base64
import io
import zipfile
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from datetime import date, timedelta
from typing import Any, ClassVar

from opti.core.domain_match import DomainMatcher
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

HAGEZI_NRD7_URL = "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/nrd7.txt"
WHOISDS_URL = "https://www.whoisds.com/whois-database/newly-registered-domains/{token}/nrd"


def whoisds_token(day: date) -> str:
    return base64.b64encode(f"{day.isoformat()}.zip".encode()).decode("ascii")


class NrdConnector(BaseConnector):
    id: ClassVar[str] = "nrd"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(
        self,
        ctx: ConnectorContext,
        config: Mapping[str, Any],
        *,
        today: Callable[[], date] = date.today,
    ) -> None:
        super().__init__(ctx, config)
        self._matcher = DomainMatcher(ctx.rules.domains)
        self._today = today

    def _scan(self, source: str, lines: Iterable[str], plan: QueryPlan) -> Iterator[RawItem]:
        for line in lines:
            d = line.strip()
            if not d or d.startswith("#") or not self._matcher.could_match(d):
                continue
            m = self._matcher.match(d)
            if m is None or m.status != "match":
                continue
            yield RawItem(
                connector_id=self.id,
                source_item_id=m.domain,
                fetched_at=utcnow(),
                url=None,
                payload={"domain": m.domain, "source": source, "matches": [m.to_dict()]},
                project_ids=plan.project_ids,
            )

    async def _hagezi(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        try:
            resp = await self.ctx.http().get(HAGEZI_NRD7_URL)
        except HttpError as e:
            self.ctx.logger().warning("hagezi NRD 下载失败：%s", e)
            return
        for item in self._scan("hagezi_nrd7", resp.text.splitlines(), plan):
            yield item

    async def _whoisds(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        last = self.ctx.get_cursor("whoisds:last_date")
        yesterday = self._today() - timedelta(days=1)
        days_back = int(self.config.get("whoisds_days_back", 3))
        for day in [yesterday - timedelta(days=i) for i in reversed(range(days_back))]:
            if last is not None and day.isoformat() <= last:
                continue
            try:
                resp = await self.ctx.http().get(WHOISDS_URL.format(token=whoisds_token(day)))
                with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                    lines = z.read(z.namelist()[0]).decode("utf-8", "replace").splitlines()
            except (HttpError, zipfile.BadZipFile, IndexError) as e:
                self.ctx.logger().warning("WhoisDS %s 下载失败，跳过：%s", day, e)
                continue
            for item in self._scan(f"whoisds:{day.isoformat()}", lines, plan):
                yield item
            self.ctx.set_cursor("whoisds:last_date", day.isoformat())

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        sources = list(self.config.get("sources", ["hagezi_nrd7"]))
        if "hagezi_nrd7" in sources:
            async for item in self._hagezi(plan):
                yield item
        if "whoisds" in sources:
            async for item in self._whoisds(plan):
                yield item
