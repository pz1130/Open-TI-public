"""核查已知品牌相关 URL 在 Common Crawl 中的历史抓取记录。"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

from opti.connectors.urlfeed import UrlFeedScanner
from opti.core.domains import parse_domain
from opti.core.urls import UrlMatcher, normalize_url
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier

INDEX_ROOT = "https://index.commoncrawl.org"
_CRAWL_ID = re.compile(r"CC-MAIN-\d{4}-\d{2}\Z")
_CAPTURE_TIME = re.compile(r"\d{14}\Z")


def _candidate(raw: Any, matcher: UrlMatcher) -> str | None:
    if not isinstance(raw, str) or raw != raw.strip():
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or parts.username or parts.password:
        return None
    if parts.query or parts.fragment or not parts.hostname or parse_domain(parts.hostname) is None:
        return None
    normalized = normalize_url(raw)
    matched = matcher.match(raw) if normalized else None
    return normalized if matched is not None and matched.kind is not None else None


def _capture(raw: Any, candidate: str) -> tuple[str, str] | None:
    if not isinstance(raw, dict) or raw.get("status") != "200":
        return None
    if raw.get("mime") not in {"text/html", "application/xhtml+xml"}:
        return None
    url = raw.get("url")
    timestamp = raw.get("timestamp")
    if not isinstance(url, str) or normalize_url(url) != candidate:
        return None
    if not isinstance(timestamp, str) or not _CAPTURE_TIME.fullmatch(timestamp):
        return None
    try:
        datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    digest = raw.get("digest")
    return timestamp, digest[:64] if isinstance(digest, str) and digest.isalnum() else ""


class CommonCrawlConnector(BaseConnector):
    id: ClassVar[str] = "common_crawl"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._matcher = UrlMatcher(ctx.rules)
        self._scanner = UrlFeedScanner(self.id, ctx.rules)

    def validate_config(self) -> None:
        raw = self.config.get("candidate_urls", [])
        if (
            not isinstance(raw, list)
            or len(raw) > 20
            or any(_candidate(value, self._matcher) is None for value in raw)
        ):
            raise ValueError("Common Crawl candidate_urls 必须是最多 20 条公开品牌相关 HTTP(S) URL")

    async def _crawls(self) -> list[str]:
        response = await self.ctx.http().get(
            f"{INDEX_ROOT}/collinfo.json",
            follow_redirects=False,
            max_retries=0,
            max_body_bytes=512 * 1024,
        )
        data = response.json()
        if not isinstance(data, list):
            raise ValueError("Common Crawl 索引目录不是列表")
        ids = {
            item["id"]
            for item in data
            if isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and _CRAWL_ID.fullmatch(item["id"])
        }
        return sorted(ids, reverse=True)[: int(self.config.get("max_crawls", 2))]

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        self._scanner.reset()
        candidates = list(
            dict.fromkeys(
                value
                for raw in self.config.get("candidate_urls", [])
                if (value := _candidate(raw, self._matcher)) is not None
            )
        )[:20]
        if not candidates:
            return
        try:
            crawls = await self._crawls()
        except (HttpError, ValueError) as exc:
            self.ctx.logger().warning("Common Crawl 索引目录读取失败：%s", type(exc).__name__)
            return
        for candidate in candidates:
            latest: tuple[str, str, str] | None = None
            for crawl_id in crawls:
                try:
                    response = await self.ctx.http().get(
                        f"{INDEX_ROOT}/{crawl_id}-index",
                        params={
                            "url": candidate,
                            "matchType": "exact",
                            "output": "json",
                            "sort": "reverse",
                            "limit": str(self.config.get("max_records", 10)),
                        },
                        follow_redirects=False,
                        max_retries=0,
                        max_body_bytes=256 * 1024,
                    )
                except HttpError as exc:
                    if exc.status in {429, 503}:
                        self.ctx.logger().warning("Common Crawl 限流，停止本次核查")
                        return
                    if exc.status != 404:
                        self.ctx.logger().warning("Common Crawl URL 查询失败：%s", exc.status)
                    continue
                try:
                    for line in response.text.splitlines():
                        parsed = _capture(json.loads(line), candidate)
                        if parsed is not None:
                            timestamp, digest = parsed
                            result = (timestamp, crawl_id, digest)
                            if latest is None or result[0] > latest[0]:
                                latest = result
                except ValueError:
                    self.ctx.logger().warning("Common Crawl URL 查询响应不是有效 JSONL")
                    continue
            if latest is None:
                continue
            timestamp, crawl_id, digest = latest
            for item in self._scanner.scan(
                [
                    (
                        candidate,
                        {
                            "confirmed": False,
                            "crawl_id": crawl_id,
                            "capture_time": datetime.strptime(timestamp, "%Y%m%d%H%M%S")
                            .replace(tzinfo=UTC)
                            .isoformat(),
                            "digest": digest,
                        },
                    )
                ],
                plan,
            ):
                # 同一次历史抓取可幂等重放；新月份的抓取仍能新增一次观测。
                yield replace(item, source_item_id=f"{candidate}#{timestamp}")
