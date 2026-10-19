"""Bounded public-page fetcher with DNS pinning and redirect validation."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from opti.core.domains import normalize_domain, to_ascii
from opti.sdk.http import HttpError, RateLimitedHttpClient

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
Resolver = Callable[[str, int], Awaitable[list[str]]]


class FetchError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        blocked: bool = False,
        retry_scheme: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.blocked = blocked
        self.retry_scheme = retry_scheme


async def resolve_addresses(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]).split("%")[0] for info in infos))


def is_public_address(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


def host_header(url: httpx.URL) -> str:
    return url.netloc.decode("ascii")


def ascii_url(raw: str) -> str | None:
    try:
        if not raw or "\\" in raw or any(ord(char) < 32 for char in raw):
            return None
        parts = urlsplit(raw)
        host = parts.hostname
        if (
            parts.scheme not in ("http", "https")
            or not host
            or parts.username is not None
            or parts.password is not None
            or "%" in parts.netloc
        ):
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if normalize_domain(host) is None:
                return None
        url = httpx.URL(raw)
        if url.scheme not in ("http", "https") or not url.host:
            return None
        return str(url.copy_with(host=to_ascii(url.host)))
    except (httpx.InvalidURL, ValueError, UnicodeError):
        return None


class SafeFetcher:
    def __init__(
        self,
        http: RateLimitedHttpClient,
        *,
        resolve: Resolver | None = None,
        timeout: float = 10.0,
        allow_private: bool = False,
        max_body_bytes: int = MAX_BODY_BYTES,
        max_redirects: int = MAX_REDIRECTS,
        truncate_body: bool = True,
    ) -> None:
        self._http = http
        self._resolve = resolve or resolve_addresses
        self._timeout = timeout
        self._allow_private = allow_private
        self._max_body = max_body_bytes
        self._max_redirects = max_redirects
        self._truncate_body = truncate_body

    async def open(self, url: str) -> tuple[httpx.Response, str, list[str]]:
        current = ascii_url(url)
        if current is None:
            raise FetchError("不合法的网页地址", blocked=True)
        redirects: list[str] = []
        first = True
        for hop in range(self._max_redirects + 1):
            try:
                response = await self._connect(current)
            except FetchError as exc:
                if first or exc.blocked or exc.status is not None:
                    raise
                raise FetchError(str(exc), retry_scheme=False) from exc
            first = False
            location = response.headers.get("location")
            if response.status_code not in _REDIRECTS or not location:
                return response, current, redirects
            if hop == self._max_redirects:
                raise FetchError("重定向次数过多", retry_scheme=False)
            try:
                next_url = httpx.URL(current).join(location)
            except (httpx.InvalidURL, ValueError) as exc:
                raise FetchError("重定向地址不合法", retry_scheme=False) from exc
            if next_url.scheme not in ("http", "https"):
                raise FetchError("不支持的重定向协议", retry_scheme=False)
            checked = ascii_url(str(next_url))
            if checked is None:
                raise FetchError("重定向地址不合法", blocked=True)
            redirects.append(current)
            current = checked
        raise AssertionError("unreachable")

    async def _connect(self, url: str) -> httpx.Response:
        parsed = httpx.URL(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            literal = ipaddress.ip_address(parsed.host)
        except ValueError:
            literal = None
        if literal is not None and not (self._allow_private or literal.is_global):
            raise FetchError("blocked_non_public_address", blocked=True)
        try:
            addresses = await asyncio.wait_for(self._resolve(parsed.host, port), self._timeout)
        except (OSError, TimeoutError) as exc:
            raise FetchError(type(exc).__name__, retry_scheme=True) from exc
        if not addresses or not (self._allow_private or all(map(is_public_address, addresses))):
            raise FetchError("blocked_non_public_address", blocked=True)
        try:
            return await self._http.get(
                str(parsed.copy_with(host=addresses[0])),
                headers={"Host": host_header(parsed), "Connection": "close"},
                extensions={"sni_hostname": parsed.raw_host.decode("ascii")},
                follow_redirects=False,
                timeout=self._timeout,
                max_retries=0,
                max_body_bytes=self._max_body,
                truncate_body=self._truncate_body,
            )
        except HttpError as exc:
            raise FetchError(str(exc), status=exc.status, retry_scheme=exc.status is None) from exc
