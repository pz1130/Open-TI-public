"""在隔离取证中对同源 favicon 计算可供人工关联的指纹。"""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import urljoin, urlsplit, urlunsplit

import mmh3

MAX_ICON_BYTES = 128 * 1024
MAX_ICON_URL = 2048


def same_origin(page_url: str, candidate_url: str) -> bool:
    try:
        page = urlsplit(page_url)
        candidate = urlsplit(candidate_url)
        return (
            page.scheme in ("http", "https")
            and candidate.scheme == page.scheme
            and page.hostname is not None
            and candidate.hostname == page.hostname
            and (page.port or (443 if page.scheme == "https" else 80))
            == (candidate.port or (443 if candidate.scheme == "https" else 80))
            and candidate.username is None
            and candidate.password is None
        )
    except ValueError:
        return False


def icon_url(page_url: str, href: str | None) -> str | None:
    """显式图标必须同源；没有声明时才尝试 /favicon.ico。"""
    if href is None:
        page = urlsplit(page_url)
        candidate = urlunsplit((page.scheme, page.netloc, "/favicon.ico", "", ""))
    else:
        if not href or "\\" in href or any(ord(c) < 32 for c in href):
            return None
        candidate = urljoin(page_url, href)
    candidate = urlunsplit(urlsplit(candidate)._replace(fragment=""))
    if len(candidate) > MAX_ICON_URL or not same_origin(page_url, candidate):
        return None
    return candidate


def favicon_fingerprint(data: bytes) -> dict[str, int | str] | None:
    """只接受常见位图图标；Shodan 兼容哈希使用 RFC 2045 Base64 换行格式。"""
    if not 16 <= len(data) <= MAX_ICON_BYTES:
        return None
    supported = (
        data.startswith(b"\x00\x00\x01\x00")  # ICO
        or data.startswith(b"\x89PNG\r\n\x1a\n")
        or data.startswith(b"\xff\xd8\xff")
        or data.startswith((b"GIF87a", b"GIF89a"))
        or (data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    )
    if not supported:
        return None
    return {
        "mmh3": mmh3.hash(base64.encodebytes(data), signed=True),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
