"""网页探测富化（设计文档 10.2"页面特征"）：读取首页标题、表单与密码框、品牌词。"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Mapping
from html import unescape
from typing import Any, ClassVar

import httpx

from opti.core.domains import to_ascii
from opti.core.text_match import TextMatcher
from opti.core.webpages import parking_signals
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.models import Tier
from opti.sdk.safefetch import (
    MAX_BODY_BYTES,
    SafeFetcher,
    ascii_url,
    is_public_address,
    resolve_addresses,
)
from opti.sdk.safefetch import FetchError as _ProbeError

__all__ = [
    "MAX_BODY_BYTES",
    "HttpProbeEnricher",
    "ascii_url",
    "is_public_address",
    "page_features",
    "resolve_addresses",
]

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_PASSWORD = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password", re.I)
_FORM = re.compile(r"<form\b", re.I)
_SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
MAX_HTML_CHARS = 2_000_000
MAX_TEXT_CHARS = 200_000


def page_features(
    html: str, matcher: TextMatcher, *, visible_text: str | None = None
) -> dict[str, Any]:
    html = html[:MAX_HTML_CHARS]
    m = _TITLE.search(html)
    title = _WS.sub(" ", unescape(m.group(1))).strip()[:300] if m else ""
    visible = _WS.sub(
        " ",
        visible_text
        if visible_text is not None
        else unescape(_TAG.sub(" ", _SCRIPT_STYLE.sub(" ", html))),
    ).strip()[:MAX_TEXT_CHARS]
    hits = matcher.match(f"{title}\n{visible[:MAX_TEXT_CHARS]}")
    return {
        "title": title,
        "text_excerpt": visible[:1500],
        "text_length": len(visible),
        "parking_signals": parking_signals(title, visible),
        "has_form": bool(_FORM.search(html)),
        "has_password_field": bool(_PASSWORD.search(html)),
        "brand_terms": sorted({h.term for h in hits if h.role == "match"}),
        "html_sha256": hashlib.sha256(html.encode("utf-8", "replace")).hexdigest(),
    }


def _page_info(
    url: str,
    resp: httpx.Response,
    matcher: TextMatcher,
    *,
    final_url: str | None = None,
    redirects: list[str] | None = None,
) -> dict[str, Any]:
    content_type = resp.headers.get("content-type", "")
    info: dict[str, Any] = {
        "reachable": True,
        "url": url,
        "status": resp.status_code,
        "final_url": str(resp.url) if final_url is None else final_url,
        "redirects": [str(r.url) for r in resp.history] if redirects is None else redirects,
        "content_type": content_type,
    }
    if "html" in content_type.lower():
        info.update(page_features(resp.text, matcher))
    return info


class HttpProbeEnricher(Enricher):
    id: ClassVar[str] = "http_probe"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain", "url")
    cache_ttl_seconds: ClassVar[int] = 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._matcher = TextMatcher(ctx.rules)

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        # 单次请求的 timeout 只限制每次读取的间隔；对方每隔几秒滴一个字节就能一直拖住 worker。
        total = float(self.config.get("total_timeout", 30.0))
        if entity_type == "url":
            url = ascii_url(value)
            if url is None:
                return {"reachable": False, "error": "invalid_url"}
            target = self._enrich_url(url)
        else:
            target = self._enrich_pinned(to_ascii(value))
        try:
            return await asyncio.wait_for(target, total)
        except TimeoutError:
            return {"reachable": False, "error": "TimeoutError"}

    @staticmethod
    def _probe_error(e: _ProbeError, url: str) -> dict[str, Any]:
        if e.blocked:
            return {"reachable": False, "error": "blocked_non_public_address"}
        if e.status is not None:
            return {"reachable": True, "url": url, "status": e.status}
        return {"reachable": False, "error": str(e)}

    async def _enrich_url(self, url: str) -> dict[str, Any]:
        try:
            resp, final_url, redirects = await self._open(url)
        except _ProbeError as e:
            return self._probe_error(e, url)
        return _page_info(url, resp, self._matcher, final_url=final_url, redirects=redirects)

    async def _enrich_pinned(self, host: str) -> dict[str, Any]:
        """先解析，再连接当时检查过的地址，避免 DNS 重绑定。"""
        last_error = "unknown"
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                resp, final_url, redirects = await self._open(url)
            except _ProbeError as e:
                if e.retry_scheme and not e.blocked and e.status is None:
                    last_error = str(e)
                    continue
                return self._probe_error(e, url)
            return _page_info(url, resp, self._matcher, final_url=final_url, redirects=redirects)
        return {"reachable": False, "error": last_error}

    async def _open(self, url: str) -> tuple[httpx.Response, str, list[str]]:
        fetcher = SafeFetcher(
            self.ctx.http(),
            resolve=lambda host, port: resolve_addresses(host, port),
            timeout=float(self.config.get("timeout", 10.0)),
            allow_private=bool(self.config.get("allow_private_targets", False)),
        )
        return await fetcher.open(url)
