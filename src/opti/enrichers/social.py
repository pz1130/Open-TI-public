"""社交账号适配器共用：头像只在内存中计算哈希，结果以 JSON 返回（可在采集节点执行）。"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from opti.core.visual import dhash_bytes
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError

AVATAR_BYTES = 1024 * 1024
RESPONSE_BYTES = 2 * 1024 * 1024
SUPPORTED_TYPES = ("social_profile", "social_search", "social_avatar")


def parse_time(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return value if value.tzinfo is not None else None


def clean(raw: Any, limit: int) -> str:
    return " ".join(raw.split())[:limit] if isinstance(raw, str) else ""


async def avatar_hashes(
    ctx: ConnectorContext, url: str, allowed: Callable[[httpx.URL], bool]
) -> dict[str, Any]:
    """只访问平台自己的 HTTPS 图片主机，不跟随重定向；图片不落盘。"""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        return {"error": "avatar_host_not_allowed"}
    if parsed.scheme != "https" or not allowed(parsed):
        return {"error": "avatar_host_not_allowed"}
    try:
        response = await ctx.http().get(
            url, follow_redirects=False, max_retries=0, max_body_bytes=AVATAR_BYTES, timeout=20
        )
    except HttpError as exc:
        if exc.status is not None and exc.status < 400:
            return {"error": "avatar_too_large"}
        return {"error": f"avatar_http_{exc.status or 'network'}"}
    data = response.content
    try:
        dhash = dhash_bytes(data)
    except ValueError:
        return {"error": "unsupported_image"}
    return {"dhash": dhash, "sha256": hashlib.sha256(data).hexdigest()}
