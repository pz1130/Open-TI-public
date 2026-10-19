"""只读查询已有域名或公网 IP 的 Pulsedive 信誉，不提交扫描。"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar

from opti.core.domains import parse_domain, to_ascii
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

API = "https://pulsedive.com/api/indicator.php"
MAX_BODY_BYTES = 128 * 1024
COOLDOWN_SECONDS = 24 * 3600
RISKS = frozenset({"unknown", "very low", "low", "medium", "high", "critical"})
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PRIVATE_SUFFIXES = frozenset(
    {"internal", "local", "localhost", "test", "invalid", "example", "onion"}
)


def public_indicator(entity_type: str, value: str) -> str | None:
    """Only existing public IP/domain indicators may leave the collector."""
    if entity_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
            return None
        return str(address) if address.is_global else None
    if entity_type == "domain":
        parts = parse_domain(value)
        if parts is None or parts.suffix in _PRIVATE_SUFFIXES or parts.suffix.isdigit():
            return None
        ascii_domain = to_ascii(parts.fqdn)
        if all(_DNS_LABEL.fullmatch(label) for label in ascii_domain.split(".")):
            return ascii_domain
    return None


def parse_indicator(doc: Any, entity_type: str, value: str) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("type") != entity_type:
        raise ValueError("Pulsedive 指标类型不匹配")
    returned = doc.get("indicator")
    if not isinstance(returned, str) or public_indicator(entity_type, returned) != value:
        raise ValueError("Pulsedive 指标值不匹配")
    risk, recommended = doc.get("risk"), doc.get("risk_recommended")
    if (
        not isinstance(risk, str)
        or risk not in RISKS
        or not isinstance(recommended, str)
        or recommended not in RISKS
    ):
        raise ValueError("Pulsedive 风险等级不合法")
    manual, retired = doc.get("manualrisk"), doc.get("retired")
    if type(manual) is not int or manual not in (0, 1):
        raise ValueError("Pulsedive 人工调整标志不合法")
    if retired is not None and (type(retired) is not int or retired not in (0, 1)):
        raise ValueError("Pulsedive 退役标志不合法")
    seen = doc.get("stamp_seen")
    if seen is not None:
        if not isinstance(seen, str):
            raise ValueError("Pulsedive 最后出现时间不合法")
        try:
            datetime.strptime(seen, "%Y-%m-%d %H:%M:%S")
        except ValueError as exc:
            raise ValueError("Pulsedive 最后出现时间不合法") from exc
    return {
        "found": True,
        "risk": risk,
        "risk_recommended": recommended,
        "manual_override": bool(manual),
        "retired": None if retired is None else bool(retired),
        "last_seen_utc": seen,
    }


class PulsediveEnricher(Enricher):
    id: ClassVar[str] = "pulsedive"
    tier: ClassVar[Tier] = Tier.PAID
    supported_types: ClassVar[tuple[str, ...]] = ("domain", "ip")
    cache_ttl_seconds: ClassVar[int] = 7 * 24 * 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._cooldown_until = 0.0

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        if entity_type not in self.supported_types:
            return {"error": "unsupported_type"}
        indicator = public_indicator(entity_type, value)
        if indicator is None:
            return {"supported": False}
        if asyncio.get_running_loop().time() < self._cooldown_until:
            return {"error": "rate_limited"}
        key = self.ctx.secret("api_key")
        if not key:
            return {"error": "missing_api_key"}
        try:
            response = await self.ctx.http().get(
                API,
                params={"indicator": indicator, "historical": "0", "schema": "0", "key": key},
                follow_redirects=False,
                max_retries=0,
                max_body_bytes=MAX_BODY_BYTES,
            )
        except HttpError as exc:
            if exc.status == 404:
                return {"found": False}
            if exc.status == 429:
                self._cooldown_until = asyncio.get_running_loop().time() + COOLDOWN_SECONDS
                return {"error": "rate_limited"}
            if exc.status == 200:
                return {"error": "invalid_response"}
            return {"error": f"http_{exc.status}" if exc.status is not None else "network"}
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        try:
            return parse_indicator(response.json(), entity_type, indicator)
        except ValueError:
            return {"error": "invalid_response"}
