"""按批准的实例与话题轮询公开 Mastodon 状态，筛出品牌相关文本。"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import quote, urlencode, urlsplit

from opti.core.documents import document_payload
from opti.core.feeds import parse_date, strip_html
from opti.core.text_match import TextMatcher
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow
from opti.sdk.safefetch import FetchError, Resolver, SafeFetcher, ascii_url

_ID = re.compile(r"[0-9]{1,30}$")


def _instance(value: Any) -> str | None:
    if not isinstance(value, str) or (canonical := ascii_url(value)) is None:
        return None
    parts = urlsplit(canonical)
    if parts.scheme != "https" or not parts.hostname or parts.port is not None:
        return None
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        return None
    if parts.username or parts.password:
        return None
    try:
        ipaddress.ip_address(parts.hostname)
    except ValueError:
        pass
    else:
        return None
    return f"https://{parts.hostname.lower()}"


def _hashtag(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    tag = value.lstrip("#")
    return tag if 2 <= len(tag) <= 64 and all(c.isalnum() or c == "_" for c in tag) else None


def _status(raw: Any) -> tuple[str, str, str, datetime, str | None] | None:
    if not isinstance(raw, dict) or raw.get("visibility") != "public":
        return None
    if raw.get("sensitive") is True or raw.get("spoiler_text") or raw.get("reblog") is not None:
        return None
    status_id = raw.get("id")
    if not isinstance(status_id, str) or not _ID.fullmatch(status_id):
        return None
    published = parse_date(raw.get("created_at"))
    if published is None:
        return None
    content = raw.get("content")
    if not isinstance(content, str) or not content:
        return None
    text = strip_html(content[:30_000])[:20_000]
    if not text:
        return None
    link = raw.get("url") or raw.get("uri")
    if not isinstance(link, str) or not link.startswith("https://"):
        return None
    url = ascii_url(link)
    if url is None:
        return None
    lang = raw.get("language")
    language = lang if isinstance(lang, str) and len(lang) <= 10 else None
    return status_id, url, text, published, language


class MastodonTagsConnector(BaseConnector):
    id: ClassVar[str] = "mastodon_tags"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self.resolve: Resolver | None = None
        public_sets = {
            name: ts.model_copy(update={"terms": terms})
            for name, ts in ctx.rules.sets.items()
            if ts.type != "executive" and not ts.private
            if (terms := tuple(term for term in ts.terms if term.remote_search))
        }
        self._matcher = TextMatcher(ctx.rules.model_copy(update={"sets": public_sets}))

    def validate_config(self) -> None:
        instances = self.config.get("instances") or []
        tags = self.config.get("hashtags") or []
        if not instances or any(_instance(value) is None for value in instances):
            raise ValueError("Mastodon instances 只能填已批准的公开 HTTPS 实例根地址")
        if not tags or any(_hashtag(value) is None for value in tags):
            raise ValueError("Mastodon hashtags 需要人工审核的有效话题")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        fetcher = SafeFetcher(
            self.ctx.http(),
            resolve=self.resolve,
            timeout=15,
            max_body_bytes=2 * 1024 * 1024,
            max_redirects=0,
            truncate_body=False,
        )
        seen: set[str] = set()
        limit = int(self.config.get("page_size", 40))
        for configured in self.config.get("instances") or []:
            origin = _instance(configured)
            if origin is None:
                continue
            for configured_tag in self.config.get("hashtags") or []:
                tag = _hashtag(configured_tag)
                if tag is None:
                    continue
                key = "since:" + hashlib.sha256(f"{origin}#{tag.lower()}".encode()).hexdigest()[:16]
                since = self.ctx.get_cursor(key)
                if since is not None and not _ID.fullmatch(since):
                    since = None
                newest = int(since) if since else 0
                max_id: str | None = None
                complete = True
                for _ in range(int(self.config.get("max_pages", 3))):
                    params = {"limit": str(limit)}
                    if since:
                        params["since_id"] = since
                    if max_id:
                        params["max_id"] = max_id
                    endpoint = (
                        f"{origin}/api/v1/timelines/tag/{quote(tag, safe='')}?{urlencode(params)}"
                    )
                    try:
                        response, _, _ = await fetcher.open(endpoint)
                        statuses = response.json()
                        if not isinstance(statuses, list):
                            raise ValueError("Mastodon 时间线不是状态列表")
                    except (FetchError, ValueError) as exc:
                        self.ctx.logger().warning("Mastodon 话题读取失败：%s", type(exc).__name__)
                        complete = False
                        break
                    ids = [int(status["id"]) for status in statuses if isinstance(status, dict)
                           and isinstance(status.get("id"), str) and _ID.fullmatch(status["id"])]  # fmt: skip
                    if ids:
                        newest = max(newest, *ids)
                    for raw in statuses:
                        parsed = _status(raw)
                        if parsed is None:
                            continue
                        status_id, url, body, published, language = parsed
                        if since and int(status_id) <= int(since):
                            continue
                        item_id = f"{origin}#{status_id}"
                        if item_id in seen or not any(
                            hit.role == "match" for hit in self._matcher.match(body)
                        ):
                            continue
                        seen.add(item_id)
                        yield RawItem(
                            connector_id=self.id,
                            source_item_id=item_id,
                            fetched_at=utcnow(),
                            url=url,
                            payload=document_payload(
                                url=url,
                                title="Mastodon 公开帖子",
                                text=body,
                                language=language,
                                published_at=published,
                                source_name=f"Mastodon · {urlsplit(origin).hostname}",
                            ),
                            project_ids=plan.project_ids,
                        )
                    if len(statuses) < limit or not ids:
                        break
                    next_max = str(min(ids))
                    if next_max == max_id:
                        complete = False
                        break
                    max_id = next_max
                else:
                    if max_id is not None:
                        complete = False
                        self.ctx.logger().warning("Mastodon 话题达到分页上限，游标未推进")
                if complete and newest > (int(since) if since else 0):
                    self.ctx.set_cursor(key, str(newest))
