"""ransomware.live victim metadata connector; institutional use requires approval."""

from __future__ import annotations

from typing import ClassVar

from opti.connectors.leakfeed import LeakFeedConnector
from opti.sdk.models import Tier


class RansomwareLiveConnector(LeakFeedConnector):
    id: ClassVar[str] = "ransomware_live"
    tier: ClassVar[Tier] = Tier.FREEMIUM
    endpoint: ClassVar[str] = "/recentvictims"
    default_base: ClassVar[str] = "https://api.ransomware.live/v2"
    default_hosts: ClassVar[tuple[str, ...]] = ("www.ransomware.live", "ransomware.live")

    def _headers(self) -> dict[str, str] | None:
        key = self.ctx.secret("api_key")
        return {str(self.config.get("api_key_header", "X-API-KEY")): key} if key else None
