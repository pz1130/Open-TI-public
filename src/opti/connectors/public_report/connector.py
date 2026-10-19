"""公众举报：数据由入口程序推送（opti intake），这里只用于合规闸门与网关白名单。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar

from opti.sdk.base import BaseConnector
from opti.sdk.models import QueryPlan, RawItem, Tier


class PublicReportConnector(BaseConnector):
    id: ClassVar[str] = "public_report"
    tier: ClassVar[Tier] = Tier.FREE

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        return
        yield
