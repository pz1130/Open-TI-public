"""PhishTank 在线已验证列表（设计文档 4.5）。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.urlfeed import UrlFeedScanner
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

DATA_URL = "https://data.phishtank.com/data/{key}/online-valid.json"


class PhishtankConnector(BaseConnector):
    id: ClassVar[str] = "phishtank"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)

    def validate_config(self) -> None:
        if not self.ctx.secret("app_key"):
            raise MissingCredential("需要 PhishTank 应用 Key（OPTI_SECRET_PHISHTANK_APP_KEY）")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        key = self.ctx.secret("app_key") or ""  # 读取时登记到日志脱敏
        try:
            resp = await self.ctx.http().get(DATA_URL.format(key=key))
            data = resp.json()
        except (HttpError, ValueError) as e:
            # 异常文本含带 Key 的 URL：只写经过脱敏的连接器日志，不向上抛
            self.ctx.logger().warning("PhishTank 下载失败：%s", e)
            return
        if not isinstance(data, list):
            self.ctx.logger().warning("PhishTank 返回格式不符合预期")
            return
        entries = (
            (
                str(e.get("url") or ""),
                {
                    "confirmed": e.get("verified") == "yes",
                    "phish_id": e.get("phish_id"),
                    "target": e.get("target"),
                    "submission_time": e.get("submission_time"),
                },
            )
            for e in data
            if isinstance(e, dict)
        )
        for item in self._scanner.scan(entries, plan):
            yield item
