"""Correlate brand-matched domains with active C2 IPs and TLS certificate fingerprints."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
import re
from collections.abc import Mapping
from typing import Any, ClassVar

from opti.core.domains import to_ascii
from opti.enrichers.tls.enricher import fetch_certificate, resolve_addresses
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
_SHA1 = re.compile(r"[0-9a-fA-F]{40}\Z")
REFRESH_SECONDS = 15 * 60


def feodo_entries(doc: Any) -> dict[str, list[dict[str, Any]]]:
    entries: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(doc, list):
        raise ValueError("Feodo 列表格式不正确")
    for row in doc:
        if not isinstance(row, dict):
            continue
        raw_ip, raw_port = row.get("ip_address"), row.get("port")
        if not isinstance(raw_ip, str):
            continue
        try:
            address = ipaddress.ip_address(raw_ip)
        except (TypeError, ValueError):
            continue
        if not address.is_global or isinstance(raw_port, bool) or not isinstance(raw_port, int):
            continue
        if not 1 <= raw_port <= 65535:
            continue
        malware = row.get("malware")
        record = {
            "ip": str(address),
            "port": raw_port,
            "malware": " ".join(malware.split())[:100] if isinstance(malware, str) else "",
        }
        entries.setdefault(str(address), []).append(record)
    return entries


def sslbl_entries(body: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for row in csv.reader(line for line in body.splitlines() if line and not line.startswith("#")):
        if len(row) != 3 or not _SHA1.fullmatch(row[1]):
            continue
        entries[row[1].lower()] = " ".join(row[2].split())[:100]
    return entries


class BotnetFeedEnricher(Enricher):
    id: ClassVar[str] = "botnet_feed"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)
    cache_ttl_seconds: ClassVar[int] = REFRESH_SECONDS

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._lock = asyncio.Lock()
        self._next_refresh = 0.0
        self._feodo: dict[str, list[dict[str, Any]]] = {}
        self._sslbl: dict[str, str] = {}

    async def _refresh(self) -> None:
        clock = asyncio.get_running_loop().time
        if clock() < self._next_refresh:
            return
        async with self._lock:
            if clock() < self._next_refresh:
                return
            try:
                response = await self.ctx.http().get(
                    FEODO_URL, follow_redirects=False, max_retries=0, max_body_bytes=4 * 1024 * 1024
                )
                if response.status_code != 200:
                    raise ValueError("Feodo 返回非成功状态")
                self._feodo = feodo_entries(response.json())
            except (HttpError, ValueError) as exc:
                self._feodo = {}
                self.ctx.logger().warning("Feodo 列表读取失败：%s", type(exc).__name__)
            try:
                response = await self.ctx.http().get(
                    SSLBL_URL, follow_redirects=False, max_retries=0, max_body_bytes=4 * 1024 * 1024
                )
                if response.status_code != 200:
                    raise ValueError("SSLBL 返回非成功状态")
                self._sslbl = sslbl_entries(response.text)
            except (HttpError, ValueError) as exc:
                self._sslbl = {}
                self.ctx.logger().warning("SSLBL 列表读取失败：%s", type(exc).__name__)
            self._next_refresh = clock() + REFRESH_SECONDS

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        host = to_ascii(value)
        try:
            addresses = await asyncio.wait_for(resolve_addresses(host, 443), 5)
        except (OSError, TimeoutError) as exc:
            return {"lookup_error": type(exc).__name__}
        try:
            parsed = list(dict.fromkeys(str(ipaddress.ip_address(addr)) for addr in addresses))
        except ValueError:
            return {"lookup_error": "invalid_address"}
        if not parsed or not all(ipaddress.ip_address(addr).is_global for addr in parsed):
            return {"lookup_error": "non_public_address"}
        await self._refresh()
        feodo = [entry for address in parsed for entry in self._feodo.get(address, [])][:10]
        sslbl: dict[str, str] | None = None
        if self._sslbl:
            try:
                der = await fetch_certificate(parsed[0], 443, server_name=host, timeout=5)
                sha1 = hashlib.sha1(der, usedforsecurity=False).hexdigest()
                if sha1 in self._sslbl:
                    sslbl = {"sha1": sha1, "reason": self._sslbl[sha1]}
            except (OSError, TimeoutError, ValueError):
                pass
        return {"feodo": feodo, "sslbl": sslbl}
