"""URLhaus 最近收录的恶意 URL（设计文档 4.5）。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.urlfeed import UrlFeedScanner
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"


class UrlhausConnector(BaseConnector):
    id: ClassVar[str] = "urlhaus"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)

    def validate_config(self) -> None:
        if not self.ctx.secret("auth_key"):
            raise MissingCredential("需要 abuse.ch Auth-Key（OPTI_SECRET_URLHAUS_AUTH_KEY）")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        key = self.ctx.secret("auth_key") or ""
        try:
            resp = await self.ctx.http().get(API_URL, headers={"Auth-Key": key})
            data = resp.json()
        except (HttpError, ValueError) as e:
            self.ctx.logger().warning("URLhaus 查询失败：%s", e)
            return
        if not isinstance(data, dict) or data.get("query_status") != "ok":
            self.ctx.logger().warning(
                "URLhaus 返回状态：%s",
                (data or {}).get("query_status") if isinstance(data, dict) else "?",
            )
            return
        entries = (
            (
                str(u.get("url") or ""),
                {
                    "confirmed": True,
                    "threat": u.get("threat"),
                    "tags": list(u.get("tags") or []),
                    "url_status": u.get("url_status"),
                    "date_added": u.get("date_added"),
                    "urlhaus_id": u.get("id"),
                },
            )
            for u in data.get("urls") or []
            if isinstance(u, dict)
        )
        for item in self._scanner.scan(entries, plan):
            yield item
