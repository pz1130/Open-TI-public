"""RansomLook recent post metadata connector (public or self-hosted)."""

from __future__ import annotations

from typing import ClassVar

from opti.connectors.leakfeed import LeakFeedConnector
from opti.sdk.models import Tier


class RansomLookConnector(LeakFeedConnector):
    id: ClassVar[str] = "ransomlook"
    tier: ClassVar[Tier] = Tier.FREE
    endpoint: ClassVar[str] = "/recent"
    default_base: ClassVar[str] = "https://www.ransomlook.io/api"
    default_hosts: ClassVar[tuple[str, ...]] = ("www.ransomlook.io", "ransomlook.io")
