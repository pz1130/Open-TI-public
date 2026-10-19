"""IP 的 RDAP 富化（设计文档 12.1）：托管网络名称、所属机构与滥用联系人，用于确定托管商投诉对象。"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any, ClassVar

from opti.enrichers.rdap.enricher import vcard_value, walk_entities
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

BOOTSTRAP_V4 = "https://data.iana.org/rdap/ipv4.json"
BOOTSTRAP_V6 = "https://data.iana.org/rdap/ipv6.json"
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_ip_bootstrap(doc: Mapping[str, Any]) -> list[tuple[IpNetwork, str]]:
    table: list[tuple[IpNetwork, str]] = []
    for service in doc.get("services", []):
        if not (isinstance(service, list) and len(service) >= 2):
            continue
        prefixes, urls = service[0], service[1]
        url = next((u for u in urls if str(u).startswith("https://")), urls[0] if urls else None)
        if not url:
            continue
        for prefix in prefixes:
            try:
                table.append((ipaddress.ip_network(str(prefix), strict=False), str(url)))
            except ValueError:
                continue
    return table


def lookup_base(table: list[tuple[IpNetwork, str]], ip: IpAddress) -> str | None:
    """最长前缀匹配：IANA 引导表里大段与其中更细的段可能指向不同的 RIR 服务。"""
    best: tuple[IpNetwork, str] | None = None
    for net, url in table:
        if (
            net.version == ip.version
            and ip in net
            and (best is None or net.prefixlen > best[0].prefixlen)
        ):
            best = (net, url)
    return best[1] if best else None


def _str(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def parse_ip_rdap(doc: Mapping[str, Any]) -> dict[str, Any]:
    org: str | None = None
    abuse: str | None = None
    for ent in walk_entities(doc.get("entities")):
        roles = ent.get("roles") or []
        if org is None and ("registrant" in roles or "administrative" in roles):
            org = vcard_value(ent, "fn")
        if abuse is None and "abuse" in roles:
            abuse = vcard_value(ent, "email")
    return {
        "network_name": _str(doc.get("name")),
        "handle": _str(doc.get("handle")),
        "country": _str(doc.get("country")),
        "start": _str(doc.get("startAddress")),
        "end": _str(doc.get("endAddress")),
        "org": org,
        "abuse_email": abuse,
    }


class IpRdapEnricher(Enricher):
    id: ClassVar[str] = "ip_rdap"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("ip",)
    cache_ttl_seconds: ClassVar[int] = 7 * 24 * 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._tables: dict[int, list[tuple[IpNetwork, str]]] = {}

    async def _base(self, ip: IpAddress) -> str | None:
        table = self._tables.get(ip.version)
        if table is None:
            default = BOOTSTRAP_V4 if ip.version == 4 else BOOTSTRAP_V6
            url = str(self.config.get(f"bootstrap_v{ip.version}", default))
            table = self._tables[ip.version] = parse_ip_bootstrap(
                (await self.ctx.http().get(url)).json()
            )
        return lookup_base(table, ip)

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return {"supported": False, "error": "invalid_ip"}
        if not ip.is_global:
            return {"supported": False}
        try:
            base = await self._base(ip)
        except (HttpError, ValueError) as e:
            status = e.status if isinstance(e, HttpError) else None
            return {"supported": None, "error": f"bootstrap:{status or type(e).__name__}"}
        if base is None:
            return {"supported": False}
        try:
            resp = await self.ctx.http().get(f"{base.rstrip('/')}/ip/{ip}")
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
        return {"supported": True, "found": True, **parse_ip_rdap(doc)}
