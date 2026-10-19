"""URL 规范化与品牌匹配（设计文档 4.5、7.3、8）。纯逻辑，不联网。

钓鱼情报源给出的是 URL：品牌词可能在主机名里（按域名处置），也可能只在路径里——例如共享托管平台上的
钓鱼页 sites.google.com/view/brand-grants，此时只能按 URL 处置，绝不能把 google.com 当成仿冒域名。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import SplitResult, unquote, unquote_plus, urlsplit, urlunsplit

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatch, DomainMatcher
from opti.core.domains import normalize_domain, parse_domain

MAX_URL_LEN = 2048
UrlKind = Literal["domain", "url"]
_TRACKING = re.compile(
    r"^(utm_[a-z0-9_]+|fbclid|gclid|msclkid|mc_cid|mc_eid|_hsenc|_hsmi|yclid)$", re.I
)
_SEP = re.compile(r"[^0-9a-z]+")


def _split(raw: str) -> SplitResult:
    s = raw.strip()
    if "://" not in s:
        # An explicit non-HTTP scheme must not become URL userinfo.
        scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s)
        if scheme and not re.match(r"^[^/]+\.[^/:]+:\d+(?:/|$)", s):
            raise ValueError("unsupported scheme")
        s = "http://" + s  # 情报源有时只给"主机名/路径"
    return urlsplit(s)


def _host(hostname: str) -> str | None:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return normalize_domain(hostname)


def normalize_url(raw: str) -> str | None:
    if not raw.strip() or len(raw) > MAX_URL_LEN or any(ord(c) < 32 for c in raw) or "\\" in raw:
        return None
    try:
        parts = _split(raw)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    host = _host(parts.hostname)
    if host is None:
        return None
    shown = f"[{host}]" if ":" in host else host  # IPv6
    default = 80 if scheme == "http" else 443
    netloc = shown if port in (None, default) else f"{shown}:{port}"
    # Preserve non-tracking fields byte-for-byte (signed URLs and bare flags).
    query = "&".join(
        field
        for field in parts.query.split("&")
        if not _TRACKING.fullmatch(unquote_plus(field.partition("=")[0]))
    )
    normalized = urlunsplit((scheme, netloc, parts.path or "/", query, ""))
    return normalized if len(normalized) <= MAX_URL_LEN else None


@dataclass(frozen=True)
class PathReason:
    reason: str  # brand_path
    token: str
    segment: str
    where: str  # userinfo / path / query


@dataclass(frozen=True)
class UrlMatch:
    url: str
    host: str
    registered: str
    host_match: DomainMatch | None
    path_reasons: tuple[PathReason, ...] = ()

    @property
    def kind(self) -> UrlKind | None:
        if self.host_match is not None:
            # 官方资产与已知合法相似方上的任何 URL 都不处理
            return "domain" if self.host_match.status == "match" else None
        return "url" if self.path_reasons else None

    def to_dict(self) -> dict[str, Any]:
        host_reasons = [asdict(r) for r in self.host_match.reasons] if self.host_match else []
        return {
            "url": self.url,
            "host": self.host,
            "registered": self.registered,
            "kind": self.kind,
            "host_status": self.host_match.status if self.host_match else None,
            "reasons": host_reasons + [asdict(r) for r in self.path_reasons],
        }


class UrlMatcher:
    def __init__(self, rules: ProjectRules) -> None:
        d = rules.domains
        self._domains = DomainMatcher(d)
        tokens = {
            t.replace("-", "").casefold()
            for t in d.brand_tokens
            if t.casefold() not in d.restricted_tokens
        }
        self._short = tuple(sorted(t for t in tokens if len(t) <= d.short_token_max_len))
        self._long = tuple(sorted(t for t in tokens if len(t) > d.short_token_max_len))
        self._affixes = frozenset(a.casefold() for a in (*d.combo_affixes, *d.fraud_affixes) if a)

    def could_match(self, raw: str) -> bool:
        """廉价预过滤：凡 match() 给出 kind 的 URL，本方法一定返回 True。"""
        lowered = unquote(raw).casefold()
        compact = _SEP.sub("", lowered)
        if any(t in compact for t in self._long) or any(t in lowered for t in self._short):
            return True
        try:
            hostname = _split(raw).hostname or ""
        except ValueError:
            return False
        return bool(hostname) and self._domains.could_match(hostname)

    def _segment_reasons(self, text: str, where: str) -> list[PathReason]:
        lowered = unquote(text).casefold()
        segments = [s for s in _SEP.split(lowered) if s]
        out: dict[tuple[str, str], PathReason] = {}
        for seg in segments:
            for t in self._short:
                if (
                    seg == t
                    or (seg.startswith(t) and seg[len(t) :] in self._affixes)
                    or (seg.endswith(t) and seg[: -len(t)] in self._affixes)
                ):
                    out.setdefault((t, where), PathReason("brand_path", t, seg, where))
        compact = "".join(segments)
        for t in self._long:
            if t in compact:
                out.setdefault((t, where), PathReason("brand_path", t, t, where))
        return list(out.values())

    def match(self, raw: str) -> UrlMatch | None:
        url = normalize_url(raw)
        if url is None:
            return None
        original = _split(raw)
        normalized = urlsplit(url)
        host = normalized.hostname or ""
        host_match = self._domains.match(host)
        if host_match is not None:
            registered = host_match.registered
        else:
            parts = parse_domain(host)
            registered = parts.registered if parts is not None else host
        reasons: list[PathReason] = []
        for where, text in (
            ("userinfo", original.username or ""),
            ("path", normalized.path),
            ("query", normalized.query),
        ):
            if text:
                reasons.extend(self._segment_reasons(text, where))
        return UrlMatch(url, host, registered, host_match, tuple(reasons))
