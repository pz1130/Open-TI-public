"""截图沙箱的请求拦截规则（设计文档 2.2、2.8、10.2）：只读访问，不连内网。

请求层先拦截非只读方法及私网目标；实际连接由同进程 SOCKS5 代理重新验证 DNS、
连接已验证的 IP，避免检查与浏览器连接之间的 DNS 重绑定窗口。
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from opti.enrichers.http_probe.enricher import is_public_address, resolve_addresses

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
INLINE_SCHEMES = frozenset({"data", "blob", "about"})
Resolver = Callable[[str, int], Awaitable[list[str]]]


async def request_allowed(
    method: str,
    url: str,
    *,
    resolve: Resolver = resolve_addresses,
    allow_private: bool = False,
) -> bool:
    if method.upper() not in ALLOWED_METHODS:
        return False
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme in INLINE_SCHEMES:
        return True
    if scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return False
    try:
        addresses = await resolve(parts.hostname, port)
    except OSError:
        return False
    return bool(addresses) and (allow_private or all(map(is_public_address, addresses)))
