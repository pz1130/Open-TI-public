"""RDAP 富化（设计文档 4.5、10.2）：注册时间、注册商、滥用联系人（用于下架）。"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, ClassVar

from opti.core.domains import parse_domain, to_ascii
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


def parse_bootstrap(doc: Mapping[str, Any]) -> dict[str, str]:
    table: dict[str, str] = {}
    for service in doc.get("services", []):
        if not (isinstance(service, list) and len(service) >= 2):
            continue
        tlds, urls = service[0], service[1]
        url = next((u for u in urls if str(u).startswith("https://")), urls[0] if urls else None)
        if url:
            for tld in tlds:
                table[str(tld).lower()] = str(url)
    return table


def vcard_value(entity: Mapping[str, Any], field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return str(item[3])
    return None


def walk_entities(entities: Any) -> Iterator[Mapping[str, Any]]:
    if not isinstance(entities, list):
        return
    for e in entities:
        if isinstance(e, dict):
            yield e
            yield from walk_entities(e.get("entities"))


def parse_rdap(doc: Mapping[str, Any]) -> dict[str, Any]:
    events = {
        e.get("eventAction"): e.get("eventDate")
        for e in doc.get("events", [])
        if isinstance(e, dict)
    }
    registrar: str | None = None
    abuse: str | None = None
    for ent in walk_entities(doc.get("entities")):
        roles = ent.get("roles") or []
        if "registrar" in roles and registrar is None:
            registrar = vcard_value(ent, "fn")
        if "abuse" in roles and abuse is None:
            abuse = vcard_value(ent, "email")
    nameservers = sorted(
        str(ns["ldhName"]).lower()
        for ns in doc.get("nameservers", [])
        if isinstance(ns, dict) and ns.get("ldhName")
    )
    status = doc.get("status")
    return {
        "registration": events.get("registration"),
        "expiration": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "registrar": registrar,
        "abuse_email": abuse,
        "status": list(status) if isinstance(status, list) else [],
        "nameservers": nameservers,
    }


class RdapEnricher(Enricher):
    id: ClassVar[str] = "rdap"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)
    cache_ttl_seconds: ClassVar[int] = 24 * 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._bootstrap: dict[str, str] | None = None

    async def _base_url(self, tld: str) -> str | None:
        if self._bootstrap is None:
            resp = await self.ctx.http().get(str(self.config.get("bootstrap_url", BOOTSTRAP_URL)))
            self._bootstrap = parse_bootstrap(resp.json())
        return self._bootstrap.get(tld)

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        parts = parse_domain(value)
        if parts is None:
            return {"supported": False, "error": "invalid_domain"}
        try:
            base = await self._base_url(to_ascii(parts.suffix.rsplit(".", 1)[-1]))
        except (HttpError, ValueError) as e:
            status = e.status if isinstance(e, HttpError) else None
            return {"supported": None, "error": f"bootstrap:{status or type(e).__name__}"}
        if base is None:
            return {"supported": False}
        url = f"{base.rstrip('/')}/domain/{to_ascii(parts.registered)}"
        try:
            resp = await self.ctx.http().get(url)
        except HttpError as e:
            if e.status == 404:
                return {"supported": True, "found": False}
            return {"supported": True, "found": None, "error": str(e.status or "network")}
        try:
            doc = resp.json()
        except ValueError:
            doc = None
        if not isinstance(doc, dict):
            return {"supported": True, "found": None, "error": "invalid_json"}
        return {"supported": True, "found": True, **parse_rdap(doc)}
