"""从公开 Jetstream v1 流筛选项目相关帖子，正文仅用于下游匹配。"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import WebSocketException

from opti.core.documents import document_payload
from opti.core.text_match import TextMatcher
from opti.sdk.base import StreamingConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

Connect = Callable[..., Any]
Sleep = Callable[[float], Awaitable[None]]
_DID = re.compile(r"did:(?:plc|web):[A-Za-z0-9._:%-]{1,200}$")
_RKEY = re.compile(r"[A-Za-z0-9._~-]{1,100}$")
_MAX_MESSAGE_BYTES = 1024 * 1024
_REWIND_US = 5_000_000
_CURSOR_FLUSH_US = 5_000_000


def _event(raw: str | bytes) -> tuple[str, str, str, datetime, int, str | None] | None:
    """只接收创建的公开文本帖子；忽略身份、账号、删除及损坏事件。"""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("kind") != "commit":
        return None
    commit = data.get("commit")
    if not isinstance(commit, dict) or commit.get("operation") != "create":
        return None
    if commit.get("collection") != "app.bsky.feed.post":
        return None
    did, rkey = data.get("did"), commit.get("rkey")
    record = commit.get("record")
    if not isinstance(did, str) or not _DID.fullmatch(did):
        return None
    if not isinstance(rkey, str) or not _RKEY.fullmatch(rkey):
        return None
    if not isinstance(record, dict) or record.get("$type") != "app.bsky.feed.post":
        return None
    body = record.get("text")
    if not isinstance(body, str) or not body.strip() or len(body) > 3_000:
        return None
    time_us = data.get("time_us")
    if isinstance(time_us, bool) or not isinstance(time_us, int) or time_us <= 0:
        return None
    try:
        observed = datetime.fromtimestamp(time_us / 1_000_000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if observed > utcnow() + timedelta(minutes=5):
        return None
    language = record.get("langs")
    lang = (
        language[0]
        if isinstance(language, list)
        and language
        and isinstance(language[0], str)
        and len(language[0]) <= 10
        else None
    )
    return did, rkey, body, observed, time_us, lang


def _url(base: str, cursor: int | None) -> str:
    parts = urlsplit(base)
    params = [(k, v) for k, v in parse_qsl(parts.query) if k not in {"cursor", "wantedCollections"}]
    params.append(("wantedCollections", "app.bsky.feed.post"))
    if cursor is not None:
        params.append(("cursor", str(max(0, cursor - _REWIND_US))))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


class BlueskyJetstreamConnector(StreamingConnector):
    id: ClassVar[str] = "bluesky_jetstream"
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
        # 节点只回传命中公开品牌词的帖子；人员及私有关键词不能在境外节点用于筛选。
        public_sets = {
            name: ts.model_copy(update={"terms": terms})
            for name, ts in ctx.rules.sets.items()
            if ts.type != "executive" and not ts.private
            if (terms := tuple(term for term in ts.terms if term.remote_search))
        }
        self._matcher = TextMatcher(ctx.rules.model_copy(update={"sets": public_sets}))
        raw_cursor = ctx.get_cursor("time_us")
        self._cursor = int(raw_cursor) if raw_cursor and raw_cursor.isdecimal() else None
        self._flushed_cursor = self._cursor or 0

    def _advance(self, time_us: int) -> None:
        if self._cursor is None or time_us > self._cursor:
            self._cursor = time_us
        if self._cursor - self._flushed_cursor >= _CURSOR_FLUSH_US:
            self.ctx.set_cursor("time_us", str(self._cursor))
            self._flushed_cursor = self._cursor

    def to_item(self, raw: str | bytes, plan: QueryPlan) -> tuple[RawItem, int] | None:
        parsed = _event(raw)
        if parsed is None:
            return None
        did, rkey, body, observed, time_us, lang = parsed
        if not any(hit.role == "match" for hit in self._matcher.match(body)):
            self._advance(time_us)
            return None
        url = f"https://bsky.app/profile/{did}/post/{rkey}"
        return (
            RawItem(
                connector_id=self.id,
                source_item_id=f"at://{did}/app.bsky.feed.post/{rkey}",
                fetched_at=utcnow(),
                url=url,
                payload=document_payload(
                    url=url,
                    title="Bluesky 公开帖子",
                    text=body,
                    language=lang,
                    published_at=observed,
                    source_name="Bluesky",
                ),
                project_ids=plan.project_ids,
            ),
            time_us,
        )

    async def stream(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        failures = 0
        reconnects = 0
        max_reconnects = self.config.get("max_reconnects")
        max_delay = float(self.config.get("reconnect_max_delay", 60))
        while True:
            url = _url(str(self.config["url"]), self._cursor)
            try:
                async with self._connect(url, max_size=_MAX_MESSAGE_BYTES, open_timeout=30) as ws:
                    failures = 0
                    async for raw in ws:
                        event = self.to_item(raw, plan)
                        if event is not None:
                            item, time_us = event
                            yield item
                            # 只有消费者成功接收后才前移游标；重放由 item_id 幂等去重。
                            self._advance(time_us)
                self.ctx.logger().warning("Jetstream 连接被服务端关闭")
            except (OSError, TimeoutError, WebSocketException) as exc:
                self.ctx.logger().warning("Jetstream 连接失败：%s", type(exc).__name__)
            failures += 1
            reconnects += 1
            if max_reconnects is not None and reconnects > int(max_reconnects):
                return
            await self._sleep(min(max_delay, 2.0**failures))
