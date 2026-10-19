"""Read victim metadata from aggregator APIs without visiting leak sites."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any, ClassVar
from urllib.parse import urlsplit

from opti.core.leakposts import leak_post_payload, parse_time
from opti.sdk.base import BaseConnector
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, utcnow

OVERLAP = timedelta(days=1)
WRAPPER_KEYS = ("victims", "data", "posts")


class LeakFeedConnector(BaseConnector):
    endpoint: ClassVar[str]
    default_base: ClassVar[str]
    default_hosts: ClassVar[tuple[str, ...]]

    def validate_config(self) -> None:
        base = str(self.config.get("api_base", self.default_base))
        parts = urlsplit(base)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
        ):
            raise ValueError("聚合源接口必须是无凭据的 HTTPS 地址")

    def _headers(self) -> dict[str, str] | None:
        return None

    async def _records(self) -> list[Any] | None:
        base = str(self.config.get("api_base", self.default_base)).rstrip("/")
        try:
            doc = (
                await self.ctx.http().get(
                    f"{base}{self.endpoint}", headers=self._headers(), follow_redirects=False
                )
            ).json()
        except (HttpError, ValueError) as e:
            self.ctx.logger().warning("读取 %s 失败：%s", self.id, e)
            return None
        if isinstance(doc, dict):
            doc = next((doc[k] for k in WRAPPER_KEYS if isinstance(doc.get(k), list)), None)
        if not isinstance(doc, list):
            self.ctx.logger().warning("%s 返回的不是受害者列表（接口可能已变化）", self.id)
            return None
        return doc

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        records = await self._records()
        if records is None:
            return
        hosts = tuple(self.config.get("link_hosts") or self.default_hosts)
        since = parse_time(self.ctx.get_cursor("since"))
        newest: datetime | None = since
        for raw in records:
            if not isinstance(raw, dict):
                continue
            payload = leak_post_payload(raw, source=self.id, allow_hosts=hosts)
            if payload is None:
                continue
            discovered = parse_time(payload["leak_post"]["discovered"])
            assert discovered is not None
            if since is not None and discovered < since - OVERLAP:
                continue
            yield RawItem(
                connector_id=self.id,
                source_item_id=str(payload["leak_post"]["key"]),
                fetched_at=utcnow(),
                url=None,
                payload=payload,
                project_ids=plan.project_ids,
            )
            if newest is None or discovered > newest:
                newest = discovered
        if newest is not None and newest != since:
            self.ctx.set_cursor("since", newest.isoformat())
