"""TLS 证书富化（设计文档 10.2）：读取对端证书的颁发者、SAN、有效期。"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
from typing import Any, ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from opti.core.domains import to_ascii
from opti.sdk.base import Enricher
from opti.sdk.models import Tier


async def fetch_certificate(
    host: str, port: int = 443, *, server_name: str | None = None, timeout: float = 10.0
) -> bytes:
    ctx = ssl.create_default_context()
    # 目的是读取仿冒站点的证书（常为自签或不匹配），因此不校验
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_name or host),
        timeout,
    )
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj is not None else None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    if not der:
        raise ssl.SSLError("对端未提供证书")
    return bytes(der)


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def parse_certificate(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = sorted(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = []
    return {
        "issuer_o": _attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _attr(cert.issuer, NameOID.COMMON_NAME),
        "subject_cn": _attr(cert.subject, NameOID.COMMON_NAME),
        "sans": sans,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "self_signed": cert.issuer == cert.subject,
    }


async def resolve_addresses(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]).split("%")[0] for info in infos))


def is_public_address(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


class TlsEnricher(Enricher):
    id: ClassVar[str] = "tls"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)
    cache_ttl_seconds: ClassVar[int] = 6 * 3600

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        host = to_ascii(value)
        port = int(self.config.get("port", 443))
        timeout = float(self.config.get("timeout", 10.0))
        try:
            addresses = await asyncio.wait_for(resolve_addresses(host, port), timeout)
        except (OSError, TimeoutError) as e:
            return {"present": False, "error": type(e).__name__}
        # 仿冒域名可能被解析到内网/本机地址：默认拒绝，避免替攻击者探测内网（SSRF）
        allow_private = bool(self.config.get("allow_private_targets", False))
        if not addresses or not (allow_private or all(map(is_public_address, addresses))):
            return {"present": False, "error": "blocked_non_public_address"}
        try:
            # 连接已检查过的地址（而不是再次解析域名），防止 DNS 重绑定
            der = await fetch_certificate(addresses[0], port, server_name=host, timeout=timeout)
        except (OSError, TimeoutError) as e:
            return {"present": False, "error": type(e).__name__}
        return {"present": True, **parse_certificate(der)}
