"""按指定域名从 CT 历史记录发现具体主机名，不把历史证书当作当前证书。"""

from __future__ import annotations

from typing import Any, ClassVar

from opti.core.certificates import certificate_domain, in_scope
from opti.sdk.base import Enricher
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

MAX_DOMAINS = 1000


class SubdomainsEnricher(Enricher):
    id: ClassVar[str] = "subdomains"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)
    cache_ttl_seconds: ClassVar[int] = 86400

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        root = certificate_domain(value)
        try:
            response = await self.ctx.http().get(
                "https://crt.sh/",
                params={"q": f"%.{root}", "output": "json"},
                timeout=30,
                max_retries=1,
                max_body_bytes=16 * 1024 * 1024,
                follow_redirects=False,
            )
            entries = response.json()
        except (HttpError, ValueError) as exc:
            return {"error": type(exc).__name__}
        if not isinstance(entries, list):
            return {"error": "invalid_ct_response"}
        domains: set[str] = {root}
        truncated = False
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            names = str(entry.get("name_value") or "").splitlines()
            names.append(str(entry.get("common_name") or ""))
            for name in names:
                try:
                    domain = certificate_domain(name)
                except ValueError:
                    continue  # 通配符不能枚举出具体主机
                if in_scope(domain, root):
                    if domain in domains or len(domains) < MAX_DOMAINS:
                        domains.add(domain)
                    else:
                        truncated = True
        return {"domains": sorted(domains), "truncated": truncated, "source": "crt.sh"}
