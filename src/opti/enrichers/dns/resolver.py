"""DNS 查询（设计文档 10.2）。"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

from opti.core.domains import to_ascii

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")


@dataclass(frozen=True)
class DnsRecords:
    name: str
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    ns: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()
    nxdomain: bool = False
    error: str | None = None

    @property
    def exists(self) -> bool | None:
        if self.nxdomain:
            return False
        if self.error:
            return None
        return any((self.a, self.aaaa, self.mx, self.ns, self.cname))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["exists"] = self.exists
        return d


class DnsResolver(Protocol):
    async def lookup(self, name: str) -> DnsRecords: ...

    async def is_registered(self, name: str) -> bool | None: ...


def _records(name: str, found: dict[str, tuple[str, ...]], error: str | None = None) -> DnsRecords:
    return DnsRecords(
        name,
        a=found.get("A", ()),
        aaaa=found.get("AAAA", ()),
        mx=found.get("MX", ()),
        ns=found.get("NS", ()),
        cname=found.get("CNAME", ()),
        error=error,
    )


class DnspythonResolver:
    def __init__(self, *, nameservers: Sequence[str] | None = None, timeout: float = 5.0) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout

    async def lookup(self, name: str) -> DnsRecords:
        qname = to_ascii(name)
        found: dict[str, tuple[str, ...]] = {}
        for rtype in RECORD_TYPES:
            try:
                answer = await self._resolver.resolve(qname, rtype)
            except dns.resolver.NXDOMAIN:
                return DnsRecords(name, nxdomain=True)
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.DNSException as e:
                # 超时、无可用服务器、标签过长（Punycode 后超过 63 字节）等：结果未知，不中断调用方
                return _records(name, found, error=type(e).__name__)
            found[rtype] = tuple(sorted(r.to_text().rstrip(".") for r in answer))
        return _records(name, found)

    async def is_registered(self, name: str) -> bool | None:
        """只查 NS 记录，判断可注册域是否已被注册：NXDOMAIN → False；超时等 → None（未知）。"""
        try:
            await self._resolver.resolve(to_ascii(name), "NS")
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            return True
        except dns.exception.DNSException:
            return None
        return True
