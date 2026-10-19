from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from opti.enrichers.dns.resolver import DnspythonResolver, DnsResolver
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.models import Tier


class DnsEnricher(Enricher):
    id: ClassVar[str] = "dns"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)
    cache_ttl_seconds: ClassVar[int] = 3600

    def __init__(
        self,
        ctx: ConnectorContext,
        config: Mapping[str, Any],
        *,
        resolver: DnsResolver | None = None,
    ) -> None:
        super().__init__(ctx, config)
        self._resolver = resolver or DnspythonResolver(
            nameservers=self.config.get("nameservers") or None,
            timeout=float(self.config.get("timeout", 5.0)),
        )

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        return (await self._resolver.lookup(value)).to_dict()
