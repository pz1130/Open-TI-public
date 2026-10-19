"""Normalize victim metadata from ransomware aggregators; never fetch leak sites."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from opti.core.vendors import host_key, normalize_org
from opti.takedown.render import defang_url

FIELDS: dict[str, tuple[str, ...]] = {
    "victim": ("victim", "post_title", "name", "title"),
    "group": ("group", "group_name"),
    "discovered": ("discovered", "published", "date"),
    "published": ("published", "attackdate"),
    "domain": ("domain", "website"),
    "country": ("country",),
    "activity": ("activity", "sector"),
    "description": ("description", "summary"),
    "links": ("url", "post_url", "permalink", "link"),
}
PUBLIC_LINK_HOSTS = {
    "ransomware_live": ("ransomware.live", "www.ransomware.live"),
    "ransomlook": ("ransomlook.io", "www.ransomlook.io"),
}
MAX_TEXT = 200
MAX_DESCRIPTION = 1000
MAX_LINKS = 5
_SLUG = re.compile(r"[^\w]+")


class LeakPostError(ValueError):
    pass


@dataclass(frozen=True)
class Post:
    key: str
    source: str
    group: str
    victim: str
    domain: str | None
    country: str | None
    activity: str | None
    discovered: datetime
    published: datetime | None
    description: str
    links: tuple[str, ...]
    other_links: tuple[str, ...]


def _clean(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = "".join(ch if unicodedata.category(ch)[0] != "C" else " " for ch in value)
    return " ".join(text.split())[:limit]


def _pick(raw: Mapping[str, Any], field: str) -> Any:
    for name in FIELDS[field]:
        value = raw.get(name)
        if value not in (None, "", []):
            return value
    return None


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def post_key(group: str, victim: str) -> str:
    g = _SLUG.sub("-", unicodedata.normalize("NFKC", group).casefold()).strip("-") or "unknown"
    v = (
        normalize_org(victim)
        or (host_key(victim) or "")
        or _SLUG.sub("-", victim.casefold()).strip("-")
    )
    key = f"{g}:{v}"
    return key if len(key) <= 300 else f"{key[:283]}-{sha256(key.encode()).hexdigest()[:16]}"


def _links(values: Any, allow_hosts: Iterable[str]) -> tuple[list[str], list[str]]:
    allowed = {h.lower() for h in allow_hosts}
    items = values if isinstance(values, list) else [values]
    links: list[str] = []
    other: list[str] = []
    for v in items:
        if not isinstance(v, str) or not v.strip():
            continue
        url = _clean(v, 500)
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            other.append(url.replace(":", "[:]").replace(".", "[.]"))
            continue
        if (
            parts.scheme == "https"
            and host in allowed
            and not parts.username
            and not parts.password
        ):
            links.append(url)
        elif parts.scheme in ("http", "https"):
            other.append(defang_url(url))
        else:
            other.append(url.replace(":", "[:]").replace(".", "[.]"))
    return list(dict.fromkeys(links))[:MAX_LINKS], list(dict.fromkeys(other))[:MAX_LINKS]


def _other_text(value: str) -> str:
    text = _clean(value, 500)
    if re.match(r"^https?://", text, flags=re.IGNORECASE):
        return defang_url(text)
    if re.match(r"^[a-z][a-z0-9+.-]*:", text, flags=re.IGNORECASE) and not text.lower().startswith(
        ("hxxp:", "hxxps:")
    ):
        return text.replace(":", "[:]", 1)
    return text


def leak_post_payload(
    raw: Mapping[str, Any], *, source: str, allow_hosts: Iterable[str]
) -> dict[str, Any] | None:
    victim = _clean(_pick(raw, "victim"), MAX_TEXT)
    group = _clean(_pick(raw, "group"), MAX_TEXT)
    discovered = parse_time(_pick(raw, "discovered"))
    if not victim or not group or discovered is None:
        return None
    published = parse_time(_pick(raw, "published"))
    domain_raw = _clean(_pick(raw, "domain"), 253)
    links, other = _links(_pick(raw, "links"), allow_hosts)
    return {
        "leak_post": {
            "source": source,
            "key": post_key(group, victim),
            "group": group,
            "victim": victim,
            "domain": host_key(domain_raw) if domain_raw else None,
            "country": _clean(_pick(raw, "country"), 50) or None,
            "activity": _clean(_pick(raw, "activity"), 100) or None,
            "discovered": discovered.isoformat(),
            "published": published.isoformat() if published else None,
            "description": _clean(_pick(raw, "description"), MAX_DESCRIPTION),
            "links": links,
            "other_links": other,
        }
    }


def parse_post(payload: Mapping[str, Any], *, allow_hosts: Iterable[str] | None = None) -> Post:
    raw = payload.get("leak_post")
    if not isinstance(raw, Mapping):
        raise LeakPostError("缺少 leak_post")
    victim, group = _clean(raw.get("victim"), MAX_TEXT), _clean(raw.get("group"), MAX_TEXT)
    discovered = parse_time(raw.get("discovered"))
    source = _clean(raw.get("source"), 50)
    if not victim or not group or discovered is None or not source:
        raise LeakPostError("受害者、团伙、来源或发现时间缺失")
    permitted = allow_hosts if allow_hosts is not None else PUBLIC_LINK_HOSTS.get(source, ())
    links, extra = _links(raw.get("links") or [], permitted)
    other = (
        [_other_text(u) for u in raw.get("other_links") or [] if isinstance(u, str)]
        if isinstance(raw.get("other_links") or [], list)
        else []
    )
    domain = raw.get("domain")
    return Post(
        key=post_key(group, victim),
        source=source,
        group=group,
        victim=victim,
        domain=host_key(domain) if isinstance(domain, str) and domain else None,
        country=_clean(raw.get("country"), 50) or None,
        activity=_clean(raw.get("activity"), 100) or None,
        discovered=discovered,
        published=parse_time(raw.get("published")),
        description=_clean(raw.get("description"), MAX_DESCRIPTION),
        links=tuple(links),
        other_links=tuple(list(dict.fromkeys([*other, *extra]))[:MAX_LINKS]),
    )
