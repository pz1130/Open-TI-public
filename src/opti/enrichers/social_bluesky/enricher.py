"""Bluesky 公开 AppView：查受保护账号资料、按名称搜索账号、计算头像哈希。"""

from __future__ import annotations

from typing import Any, ClassVar

from opti.core.social import BIO_CHARS, Profile
from opti.enrichers.social import RESPONSE_BYTES, SUPPORTED_TYPES, avatar_hashes, clean, parse_time
from opti.sdk.base import Enricher
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

DEFAULT_APPVIEW = "https://public.api.bsky.app"
SEARCH_LIMIT = 50
_GONE_LABELS = frozenset({"!takedown", "!suspend"})


def _profile(raw: Any) -> Profile | None:
    if not isinstance(raw, dict):
        return None
    did, handle = raw.get("did"), raw.get("handle")
    if not isinstance(did, str) or not did.startswith("did:") or not isinstance(handle, str):
        return None
    if not handle or handle == "handle.invalid":  # 域名验证失败的账号没有可信的账号名
        return None
    labels = raw.get("labels")
    labels = labels if isinstance(labels, list) else []
    avatar = raw.get("avatar")
    return Profile(
        platform_id=did,
        handle=handle.lower(),
        display_name=clean(raw.get("displayName"), 200),
        profile_url=f"https://bsky.app/profile/{did}",
        registered_at=parse_time(raw.get("createdAt")),
        bio=raw["description"][:BIO_CHARS] if isinstance(raw.get("description"), str) else "",
        avatar_url=avatar if isinstance(avatar, str) else None,
        suspended=any(isinstance(x, dict) and x.get("val") in _GONE_LABELS for x in labels),
    )


class BlueskyEnricher(Enricher):
    id: ClassVar[str] = "social_bluesky"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = SUPPORTED_TYPES

    def _url(self, method: str) -> str:
        base = str(self.config.get("appview_url") or DEFAULT_APPVIEW).rstrip("/")
        return f"{base}/xrpc/{method}"

    async def _get(self, method: str, params: dict[str, str]) -> Any:
        response = await self.ctx.http().get(
            self._url(method),
            params=params,
            follow_redirects=False,
            max_retries=1,
            max_body_bytes=RESPONSE_BYTES,
            timeout=20,
        )
        return response.json()

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        if entity_type == "social_profile":
            try:
                data = await self._get("app.bsky.actor.getProfile", {"actor": value})
            except HttpError as exc:
                # 账号不存在、被下架或停用时 AppView 返回 400（Profile not found / AccountTakedown）
                if exc.status == 400:
                    return {"not_found": True}
                return {"error": f"http_{exc.status or 'network'}"}
            except ValueError:
                return {"error": "invalid_response"}
            profile = _profile(data)
            return {"profile": profile.to_json()} if profile else {"error": "invalid_response"}
        if entity_type == "social_search":
            try:
                data = await self._get(
                    "app.bsky.actor.searchActors", {"q": value, "limit": str(SEARCH_LIMIT)}
                )
            except HttpError as exc:
                return {"error": f"http_{exc.status or 'network'}"}
            except ValueError:
                return {"error": "invalid_response"}
            if not isinstance(data, dict) or not isinstance(data.get("actors"), list):
                return {"error": "invalid_response"}
            profiles = [p for p in map(_profile, data["actors"]) if p is not None]
            return {"profiles": [p.to_json() for p in profiles]}
        if entity_type == "social_avatar":
            return await avatar_hashes(self.ctx, value, lambda url: url.host == "cdn.bsky.app")
        return {"error": "unsupported_type"}
