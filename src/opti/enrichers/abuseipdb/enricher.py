"""只读 AbuseIPDB API v2 Check；不读取举报正文，不上报或拉取黑名单。"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar

from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

API = "https://api.abuseipdb.com/api/v2/check"
MAX_BODY_BYTES = 8192
MAX_AGE_DAYS = "90"
COOLDOWN_SECONDS = 24 * 3600


def parse_check(doc: Any, ip: str) -> dict[str, Any]:
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        raise ValueError("AbuseIPDB 响应缺少 data")
    raw_ip = data.get("ipAddress")
    if not isinstance(raw_ip, str):
        raise ValueError("AbuseIPDB IP 不合法")
    try:
        returned = ipaddress.ip_address(raw_ip)
    except ValueError as exc:
        raise ValueError("AbuseIPDB IP 不合法") from exc
    if str(returned) != ip or data.get("isPublic") is not True:
        raise ValueError("AbuseIPDB 响应 IP 不匹配或非公网")
    confidence, reports = data.get("abuseConfidenceScore"), data.get("totalReports")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, int)
        or not 0 <= confidence <= 100
    ):
        raise ValueError("AbuseIPDB 置信度不合法")
    if isinstance(reports, bool) or not isinstance(reports, int) or reports < 0:
        raise ValueError("AbuseIPDB 举报计数不合法")
    whitelisted = data.get("isWhitelisted")
    if whitelisted is not None and not isinstance(whitelisted, bool):
        raise ValueError("AbuseIPDB 白名单状态不合法")
    last = data.get("lastReportedAt")
    if last is not None:
        if not isinstance(last, str):
            raise ValueError("AbuseIPDB 举报时间不合法")
        try:
            if datetime.fromisoformat(last.replace("Z", "+00:00")).tzinfo is None:
                raise ValueError("missing timezone")
        except ValueError as exc:
            raise ValueError("AbuseIPDB 举报时间不合法") from exc
    return {
        "abuse_confidence": confidence,
        "total_reports": reports,
        "is_whitelisted": whitelisted,
        "last_reported_at": last,
        "max_age_days": int(MAX_AGE_DAYS),
    }


class AbuseIpdbEnricher(Enricher):
    id: ClassVar[str] = "abuseipdb"
    tier: ClassVar[Tier] = Tier.PAID
    supported_types: ClassVar[tuple[str, ...]] = ("ip",)
    cache_ttl_seconds: ClassVar[int] = 24 * 3600

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
        if not address.is_global:
            return {"supported": False}
        if asyncio.get_running_loop().time() < self._cooldown_until:
            return {"error": "rate_limited"}
        key = self.ctx.secret("api_key")
        if not key:
            return {"error": "missing_api_key"}
        ip = str(address)
        try:
            response = await self.ctx.http().get(
                API, params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
                headers={"Key": key, "Accept": "application/json"},
                follow_redirects=False, max_retries=0, max_body_bytes=MAX_BODY_BYTES,
            )  # fmt: skip
        except HttpError as exc:
            if exc.status == 429:
                self._cooldown_until = asyncio.get_running_loop().time() + COOLDOWN_SECONDS
                return {"error": "rate_limited"}
            if exc.status == 200:
                return {"error": "invalid_response"}
            return {"error": f"http_{exc.status}" if exc.status is not None else "network"}
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        try:
            return parse_check(response.json(), ip)
        except ValueError:
            return {"error": "invalid_response"}
