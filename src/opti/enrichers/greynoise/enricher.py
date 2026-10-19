"""GreyNoise Community：仅查询已有公网 IPv4 指标的扫描/RIOT 上下文。"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Mapping
from datetime import date
from typing import Any, ClassVar

from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

API = "https://api.greynoise.io/v3/community"
MAX_BODY_BYTES = 4096
COOLDOWN_SECONDS = 24 * 3600
CLASSIFICATIONS = frozenset({"benign", "unknown", "malicious"})


def parse_community(doc: Any, ip: str) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("ip") != ip:
        raise ValueError("GreyNoise 响应 IP 不匹配")
    noise, riot, classification = doc.get("noise"), doc.get("riot"), doc.get("classification")
    if not isinstance(noise, bool) or not isinstance(riot, bool):
        raise ValueError("GreyNoise 响应缺少布尔字段")
    if not isinstance(classification, str) or classification not in CLASSIFICATIONS:
        raise ValueError("GreyNoise 响应分类不合法")
    name = doc.get("name")
    last_seen = doc.get("last_seen")
    if last_seen is not None:
        if not isinstance(last_seen, str):
            raise ValueError("GreyNoise 日期不合法")
        try:
            date.fromisoformat(last_seen)
        except ValueError as exc:
            raise ValueError("GreyNoise 日期不合法") from exc
    return {
        "found": True,
        "noise": noise,
        "riot": riot,
        "classification": classification,
        "name": " ".join(name.split())[:160] if isinstance(name, str) else None,
        "last_seen": last_seen,
    }


class GreyNoiseEnricher(Enricher):
    id: ClassVar[str] = "greynoise"
    tier: ClassVar[Tier] = Tier.FREEMIUM
    supported_types: ClassVar[tuple[str, ...]] = ("ip",)
    cache_ttl_seconds: ClassVar[int] = 7 * 24 * 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._cooldown_until = 0.0

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        if entity_type != "ip":
            return {"error": "unsupported_type"}
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return {"error": "invalid_ip"}
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            return {"supported": False}
        if asyncio.get_running_loop().time() < self._cooldown_until:
            return {"error": "rate_limited"}
        key = self.ctx.secret("api_key")
        if not key:
            return {"error": "missing_api_key"}
        ip = str(address)
        try:
            response = await self.ctx.http().get(
                f"{API}/{ip}", headers={"key": key}, follow_redirects=False,
                max_retries=0, max_body_bytes=MAX_BODY_BYTES,
            )  # fmt: skip
        except HttpError as exc:
            if exc.status == 404:
                return {"found": False, "noise": False, "riot": False}
            if exc.status == 429:
                self._cooldown_until = asyncio.get_running_loop().time() + COOLDOWN_SECONDS
                return {"error": "rate_limited"}
            if exc.status == 200:  # 响应体超过上限
                return {"error": "invalid_response"}
            return {"error": f"http_{exc.status}" if exc.status is not None else "network"}
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        try:
            return parse_community(response.json(), ip)
        except ValueError:
            return {"error": "invalid_response"}
