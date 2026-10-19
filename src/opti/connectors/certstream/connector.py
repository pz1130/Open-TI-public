"""证书透明度实时流连接器（设计文档 4.5、7.3）。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import asdict
from typing import Any, ClassVar

from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import WebSocketException

from opti.connectors.certstream.parser import CertEvent, parse_message
from opti.core.domain_match import DomainMatch, DomainMatcher
from opti.sdk.base import StreamingConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

Connect = Callable[..., Any]
Sleep = Callable[[float], Awaitable[None]]
_MAX_MESSAGE_BYTES = 4 * 1024 * 1024


def unique_domains(matches: list[DomainMatch]) -> list[DomainMatch]:
    """同一张证书里 example.com 与 *.example.com 规范化后相同，只保留第一次出现。"""
    seen: set[str] = set()
    out: list[DomainMatch] = []
    for m in matches:
        if m.domain not in seen:
            seen.add(m.domain)
            out.append(m)
    return out


class CertstreamConnector(StreamingConnector):
    id: ClassVar[str] = "certstream"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(
        self,
        ctx: ConnectorContext,
        config: Mapping[str, Any],
        *,
        connect: Connect = ws_connect,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        super().__init__(ctx, config)
        self._connect = connect
        self._sleep = sleep
        self._matcher = DomainMatcher(ctx.rules.domains)

    def select(self, event: CertEvent) -> list[DomainMatch]:
        out: list[DomainMatch] = []
        for d in event.all_domains:
            if not self._matcher.could_match(d):
                continue
            m = self._matcher.match(d)
            if m is not None and m.status == "match":
                out.append(m)
        return unique_domains(out)

    def extra_payload(self, event: CertEvent) -> dict[str, Any]:
        return {}

    def to_item(self, event: CertEvent, plan: QueryPlan) -> RawItem | None:
        matches = self.select(event)
        if not matches:
            return None
        return RawItem(
            connector_id=self.id,
            source_item_id=event.sha256 or f"{event.source}:{event.seen}",
            fetched_at=utcnow(),
            url=None,
            payload={
                "cert": asdict(event),
                "matches": [m.to_dict() for m in matches],
                **self.extra_payload(event),
            },
            project_ids=plan.project_ids,
        )

    async def stream(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        url = str(self.config["url"])
        max_reconnects = self.config.get("max_reconnects")
        max_delay = float(self.config.get("reconnect_max_delay", 60))
        log = self.ctx.logger()
        failures = 0
        while True:
            try:
                async with self._connect(url, max_size=_MAX_MESSAGE_BYTES, open_timeout=30) as ws:
                    failures = 0
                    log.info("已连接 %s", url)
                    async for raw in ws:
                        event = parse_message(raw)
                        if event is None:
                            continue
                        item = self.to_item(event, plan)
                        if item is not None:
                            yield item
                log.warning("连接被服务端关闭：%s", url)
            except (OSError, TimeoutError, WebSocketException) as e:
                log.warning("连接失败：%s（%s）", url, type(e).__name__)
            failures += 1
            if max_reconnects is not None and failures > int(max_reconnects):
                return
            await self._sleep(min(max_delay, 2.0**failures))
