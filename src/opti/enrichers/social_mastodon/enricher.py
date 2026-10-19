"""Mastodon 公开接口：在账号所在实例查资料、在所配置实例搜索账号、计算头像哈希。

Mastodon 没有全网搜索，只覆盖所配置实例已知的账号；不带令牌，不用 resolve 让实例去远程抓取。
"""

from __future__ import annotations

import html
import re
import time
from typing import Any, ClassVar

import httpx

from opti.core.social import BIO_CHARS, Profile, valid_host
from opti.enrichers.social import (
    RESPONSE_BYTES,
    SUPPORTED_TYPES,
    avatar_hashes,
    clean,
    parse_time,
)
from opti.sdk.base import Enricher
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

SEARCH_LIMIT = 40
DENIED_FOR = 3600.0  # 实例拒绝匿名访问后一小时内不再请求
_TAG = re.compile(r"<[^>]+>")
_DEFAULT_AVATAR = "/avatars/original/missing.png"


def _text(note: Any) -> str:
    if not isinstance(note, str):
        return ""
    return clean(html.unescape(_TAG.sub(" ", note)), BIO_CHARS)


def _host(value: str) -> str | None:
    try:
        return httpx.URL(value).host
    except httpx.InvalidURL:
        return None


def _profile(raw: Any, instance: str) -> Profile | None:
    if not isinstance(raw, dict):
        return None
    uri, acct, username = raw.get("uri"), raw.get("acct"), raw.get("username")
    if not isinstance(uri, str) or not uri.startswith("https://"):
        return None
    if not isinstance(acct, str) or not isinstance(username, str) or not acct:
        return None
    handle = (acct if "@" in acct else f"{acct}@{instance}").lower()
    # url 由远程账号自填，可指向任意网址；只认账号所在服务器（handle 域名或 uri 主机）上的链接
    url = raw.get("url")
    home = {handle.partition("@")[2], _host(uri)}
    if not isinstance(url, str) or not url.startswith("https://") or _host(url) not in home:
        url = uri
    avatar = raw.get("avatar_static")
    if not isinstance(avatar, str) or _DEFAULT_AVATAR in avatar:
        avatar = None
    return Profile(
        platform_id=uri,
        handle=handle,
        display_name=clean(raw.get("display_name"), 200),
        profile_url=url,
        registered_at=parse_time(raw.get("created_at")),
        bio=_text(raw.get("note")),
        avatar_url=avatar,
        suspended=raw.get("suspended") is True,
    )


class MastodonEnricher(Enricher):
    id: ClassVar[str] = "social_mastodon"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = SUPPORTED_TYPES

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._denied: dict[str, float] = {}

    def _instances(self) -> list[str]:
        raw = self.config.get("instances", ["mastodon.social"])
        items = raw if isinstance(raw, list) else []
        hosts = [valid_host(item.strip().lower()) for item in items if isinstance(item, str)]
        return list(dict.fromkeys(h for h in hosts if h))[:10]

    async def _get(self, instance: str, path: str, params: dict[str, str]) -> Any:
        response = await self.ctx.http().get(
            f"https://{instance}{path}",
            params=params,
            follow_redirects=False,
            max_retries=1,
            max_body_bytes=RESPONSE_BYTES,
            timeout=20,
        )
        return response.json()

    async def _lookup(self, handle: str) -> dict[str, Any]:
        user, _, instance = handle.partition("@")
        if not user or valid_host(instance) is None:
            return {"error": "invalid_handle"}
        try:
            data = await self._get(instance, "/api/v1/accounts/lookup", {"acct": user})
        except HttpError as exc:
            if exc.status in (404, 410):
                return {"not_found": True}
            return {"error": f"http_{exc.status or 'network'}"}
        except ValueError:
            return {"error": "invalid_response"}
        profile = _profile(data, instance)
        return {"profile": profile.to_json()} if profile else {"error": "invalid_response"}

    async def _search(self, query: str) -> dict[str, Any]:
        instances = self._instances()
        if not instances:
            return {"error": "no_instances"}
        profiles: dict[str, Profile] = {}
        failed = 0
        now = time.monotonic()
        for instance in instances:
            if self._denied.get(instance, 0.0) > now:
                failed += 1
                continue
            try:
                data = await self._get(
                    instance,
                    "/api/v2/search",
                    {"q": query, "type": "accounts", "limit": str(SEARCH_LIMIT)},
                )
            except HttpError as exc:
                if exc.status in (401, 403):  # 不尝试绕过实例的访问限制
                    self._denied[instance] = now + DENIED_FOR
                failed += 1
                continue
            except ValueError:
                failed += 1
                continue
            if not isinstance(data, dict) or not isinstance(data.get("accounts"), list):
                failed += 1
                continue
            for raw in data["accounts"]:
                profile = _profile(raw, instance)
                if profile is not None:
                    profiles.setdefault(profile.platform_id, profile)
        if failed == len(instances):
            return {"error": "all_instances_failed", "failed_instances": failed}
        return {"profiles": [p.to_json() for p in profiles.values()], "failed_instances": failed}

    def _avatar_host(self, url: httpx.URL) -> bool:
        return any(url.host == i or url.host.endswith(f".{i}") for i in self._instances())

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        if entity_type == "social_profile":
            return await self._lookup(value)
        if entity_type == "social_search":
            return await self._search(value)
        if entity_type == "social_avatar":
            return await avatar_hashes(self.ctx, value, self._avatar_host)
        return {"error": "unsupported_type"}
