"""冒充社交账号检测的纯函数：账号名规范化、相似比较与排除规则。

平台适配器（富化器）把资料转成 Profile 的 JSON 形式，以便在采集节点执行后传回；
比较结果只是人工复核线索，头像相似不作为身份证明。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from opti.core.domains import skeleton
from opti.core.scoring import AccountFacts
from opti.core.visual import HASH_PATTERN, hash_distance

PLATFORMS = ("bluesky", "mastodon")
MAX_QUERIES = 7
MAX_QUERY_CHARS = 100
BIO_CHARS = 500
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_MASTODON_USER = re.compile(r"[a-z0-9_]{1,30}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CLAIM = re.compile(r"\b(?:official|verified)\b")
_CLAIM_ZH = ("官方", "官网", "认证")


@dataclass(frozen=True)
class Avatar:
    dhash: str
    sha256: str

    @classmethod
    def from_json(cls, data: Any) -> Avatar | None:
        if not isinstance(data, Mapping):
            return None
        dhash, sha256 = data.get("dhash"), data.get("sha256")
        if not isinstance(dhash, str) or not isinstance(sha256, str):
            return None
        if HASH_PATTERN.fullmatch(dhash) is None or _SHA256.fullmatch(sha256) is None:
            return None
        return cls(dhash, sha256)


@dataclass(frozen=True)
class Profile:
    """平台账号资料中判定所需的字段；platform_id 为永久 ID（Bluesky DID、Mastodon 账号 URI）。"""

    platform_id: str
    handle: str
    display_name: str
    profile_url: str
    registered_at: datetime | None
    bio: str
    avatar_url: str | None
    suspended: bool = False

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["registered_at"] = self.registered_at.isoformat() if self.registered_at else None
        return data

    @classmethod
    def from_json(cls, data: Any) -> Profile | None:
        """校验采集节点传回的资料；字段类型不对时整条丢弃，注册时间无法解析时视为未知。"""
        if not isinstance(data, Mapping):
            return None
        required = [data.get(k) for k in ("platform_id", "handle", "profile_url")]
        if not all(isinstance(v, str) and v for v in required):
            return None
        if not str(required[2]).startswith("https://"):
            return None  # 主页链接会成为告警与下架对象，只接受 HTTPS
        display, bio, avatar = data.get("display_name"), data.get("bio"), data.get("avatar_url")
        if not isinstance(display, str) or not isinstance(bio, str):
            return None
        if avatar is not None and not isinstance(avatar, str):
            return None
        registered: datetime | None = None
        raw = data.get("registered_at")
        if isinstance(raw, str):
            try:
                registered = datetime.fromisoformat(raw)
            except ValueError:
                registered = None
            if registered is not None and registered.tzinfo is None:
                registered = None
        return cls(
            platform_id=str(required[0]),
            handle=str(required[1]),
            display_name=display,
            profile_url=str(required[2]),
            registered_at=registered,
            bio=bio[:BIO_CHARS],
            avatar_url=avatar,
            suspended=data.get("suspended") is True,
        )


@dataclass(frozen=True)
class Protected:
    platform: str
    handle: str
    platform_id: str | None
    display_name: str | None
    avatar: Avatar | None


def normalize_name(text: str) -> str:
    """同形字骨架后只保留字母数字（含中日韩文字），去掉空白、标点、emoji 与分隔符。"""
    return "".join(c for c in skeleton(text) if c.isalnum())


def valid_host(raw: str) -> str | None:
    labels = raw.split(".")
    if len(raw) > 253 or len(labels) < 2 or not labels[-1][:1].isalpha():
        return None
    return raw if all(_LABEL.match(label) for label in labels) else None


def normalize_handle(platform: str, raw: str) -> str:
    """规范化受保护账号名：Bluesky 为 handle，Mastodon 为 user@instance。"""
    value = raw.strip().lower().removeprefix("@")
    if platform == "bluesky":
        if valid_host(value) is None:
            raise ValueError("Bluesky 账号名应为域名形式，如 example.bsky.social")
        return value
    if platform == "mastodon":
        user, _, instance = value.partition("@")
        if not _MASTODON_USER.match(user) or valid_host(instance) is None:
            raise ValueError("Mastodon 账号名应为 user@instance 形式")
        return value
    raise ValueError("不支持的平台")


def local_part(platform: str, handle: str) -> str:
    return handle.split("@")[0] if platform == "mastodon" else handle.split(".")[0]


def handle_host(platform: str, handle: str) -> str:
    return handle.partition("@")[2] if platform == "mastodon" else handle


def search_queries(protected: Protected, extras: Iterable[str]) -> list[str]:
    """显示名、账号名本地部分与补充搜索词；规范化后去重，太短的跳过，最多 7 个。"""
    out: list[str] = []
    seen: set[str] = set()
    names = [protected.display_name or "", local_part(protected.platform, protected.handle)]
    for raw in [*names, *extras]:
        query = " ".join(raw.split())[:MAX_QUERY_CHARS]
        key = normalize_name(query)
        if len(key) < 2 or key in seen:
            continue
        seen.add(key)
        out.append(query)
    return out[:MAX_QUERIES]


def _display(protected: str, candidate: str) -> str | None:
    if not protected or not candidate:
        return None
    if candidate == protected:
        return "same"
    if fuzz.ratio(protected, candidate) >= 85 or (len(protected) >= 4 and protected in candidate):
        return "similar"
    return None


def _handle(protected: str, candidate: str) -> str | None:
    if not protected or not candidate:
        return None
    if candidate == protected or (
        len(protected) >= 5 and Levenshtein.distance(protected, candidate) <= 2
    ):
        return "same"
    if len(protected) >= 4 and protected in candidate:
        return "contains"
    return None


def _avatar(official: Avatar | None, avatar: Avatar | None) -> int | None:
    if official is None or avatar is None:
        return None
    if official.sha256 == avatar.sha256:
        return 0
    try:
        return hash_distance(official.dhash, avatar.dhash)
    except ValueError:
        return None  # 纯色等区分力不足的头像只认字节完全相同


def name_facts(protected: Protected, candidate: Profile, now: datetime) -> AccountFacts:
    """除头像外的信号；没有名称信号的候选不必下载头像。"""
    display = normalize_name(protected.display_name or "")
    bio = candidate.bio.casefold()
    claim = bool(_CLAIM.search(bio)) or any(word in bio for word in _CLAIM_ZH)
    if len(display) >= 4 and display in normalize_name(candidate.bio):
        claim = True
    age = (
        max(0, (now - candidate.registered_at).days)
        if candidate.registered_at is not None
        else None
    )
    return AccountFacts(
        display=_display(display, normalize_name(candidate.display_name)),
        handle=_handle(
            normalize_name(local_part(protected.platform, protected.handle)),
            normalize_name(local_part(protected.platform, candidate.handle)),
        ),
        bio_claim=claim,
        age_days=age,
    )


def compare(
    protected: Protected, candidate: Profile, avatar: Avatar | None, now: datetime
) -> AccountFacts:
    facts = name_facts(protected, candidate, now)
    return AccountFacts(
        display=facts.display,
        handle=facts.handle,
        avatar_distance=_avatar(protected.avatar, avatar),
        bio_claim=facts.bio_claim,
        age_days=facts.age_days,
    )


def excluded(
    protected: Protected,
    candidate: Profile,
    allowed: Iterable[str],
    official_domains: Iterable[str],
) -> bool:
    """受保护账号本身、已知合法账号、账号所在域名属于本机构官方域名的，都不算冒充。"""
    if candidate.platform_id == protected.platform_id or candidate.handle == protected.handle:
        return True
    known = {item.casefold() for item in allowed}
    if candidate.handle.casefold() in known or candidate.platform_id.casefold() in known:
        return True
    host = handle_host(protected.platform, candidate.handle.casefold())
    return any(host == d or host.endswith(f".{d}") for d in official_domains)
