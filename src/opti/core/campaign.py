"""Conservative, exact fingerprints for analyst-only alert correlation and campaign grouping.

关联告警线索只用 TLS 与 favicon 的 SHA-256 直接比对；仿冒活动（设计文档 8 实体聚类）
另加页面 HTML SHA-256 与公网 IP，被太多发现共用的值视为共享基础设施，不作关联依据。
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
Signal = Literal["tls_sha256", "favicon_sha256"]
SIGNALS: tuple[Signal, ...] = ("tls_sha256", "favicon_sha256")
GroupSignal = Literal["tls_sha256", "favicon_sha256", "html_sha256", "ip"]
GROUP_SIGNALS: tuple[GroupSignal, ...] = ("tls_sha256", "favicon_sha256", "html_sha256", "ip")
SignalValue = tuple[str, str]  # (信号种类, 值)
MAX_LINKS = 5
MAX_IGNORED = 20
MAX_IPS = 64  # 每个实体最多取多少个 DNS 地址


def _path(value: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _sha(value: Any) -> str | None:
    return value if isinstance(value, str) and _SHA256.fullmatch(value) else None


def fingerprints(enrichment: Any) -> dict[str, str]:
    """Ignore malformed or missing enrichments; never correlate on weak mmh3 alone."""
    values: dict[str, str] = {}
    for name, path in (
        ("tls_sha256", ("tls", "data", "sha256")),
        ("favicon_sha256", ("screenshot", "data", "favicon", "sha256")),
    ):
        if digest := _sha(_path(enrichment, *path)):
            values[name] = digest
    return values


def shared_signals(left: dict[str, str], right: dict[str, str]) -> list[Signal]:
    return [name for name in SIGNALS if name in left and left[name] == right.get(name)]


def _public_ip(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    return address.compressed if address.is_global else None


def group_signals(entity_type: str, enrichment: Any) -> frozenset[SignalValue]:
    """取实体当前富化结果中的四类精确信号；格式不对或缺失的一律忽略。"""
    if entity_type not in ("domain", "url") or not isinstance(enrichment, dict):
        return frozenset()
    out: set[SignalValue] = set()
    if entity_type == "domain" and (tls := _sha(_path(enrichment, "tls", "data", "sha256"))):
        out.add(("tls_sha256", tls))
    icon = _path(enrichment, "screenshot", "data", "favicon")
    # 与本机构图标参考值相同只说明对方复制了我们的图标，不说明是同一运营者
    if (
        isinstance(icon, dict)
        and not icon.get("reference_matches")
        and (digest := _sha(icon.get("sha256")))
    ):
        out.add(("favicon_sha256", digest))
    if html := _sha(_path(enrichment, "http_probe", "data", "html_sha256")):
        out.add(("html_sha256", html))
    if entity_type == "domain":
        dns = _path(enrichment, "dns", "data")
        if isinstance(dns, dict):
            for key in ("a", "aaaa"):
                values = dns.get(key)
                if isinstance(values, list):
                    for raw in values[:MAX_IPS]:
                        if ip := _public_ip(raw):
                            out.add(("ip", ip))
    return frozenset(out)


def share_counts(signal_sets: Iterable[frozenset[SignalValue]]) -> Counter[SignalValue]:
    counts: Counter[SignalValue] = Counter()
    for signals in signal_sets:
        counts.update(signals)
    return counts


def signature(finding_ids: Iterable[int]) -> str:
    joined = ",".join(str(i) for i in sorted(set(finding_ids)))
    return hashlib.sha256(joined.encode()).hexdigest()


@dataclass(frozen=True)
class Node:
    finding_id: int
    signals: frozenset[SignalValue]
    active: bool  # 有未关闭（open / acknowledged）告警


@dataclass(frozen=True)
class Confirmed:
    campaign_id: int
    members: frozenset[int]  # member 与 pending
    excluded: frozenset[int]


@dataclass(frozen=True)
class Link:
    kind: str
    value: str
    with_finding: int

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "with_finding": self.with_finding}


@dataclass(frozen=True)
class Group:
    finding_ids: tuple[int, ...]
    links: Mapping[int, tuple[Link, ...]]
    ignored: tuple[tuple[str, str, int], ...]

    def ignored_dicts(self) -> list[dict[str, Any]]:
        return [{"kind": k, "value": v, "count": n} for k, v, n in self.ignored]


@dataclass(frozen=True)
class Grouping:
    candidates: tuple[Group, ...]
    extensions: Mapping[int, Group]  # 已确认活动 id → 本轮新增的待确认成员


def _order(value: SignalValue) -> tuple[int, str]:
    kind = value[0]
    return (GROUP_SIGNALS.index(kind) if kind in GROUP_SIGNALS else len(GROUP_SIGNALS), value[1])


def group(
    nodes: Sequence[Node],
    counts: Mapping[SignalValue, int],
    confirmed: Sequence[Confirmed],
    *,
    max_share: int,
    min_members: int,
    enabled: frozenset[str],
) -> Grouping:
    by_id = {n.finding_id: n for n in nodes}
    usable = {
        fid: sorted(
            (v for v in n.signals if v[0] in enabled and counts.get(v, 0) <= max_share),
            key=_order,
        )
        for fid, n in by_id.items()
    }
    buckets: dict[SignalValue, list[int]] = {}
    for fid in sorted(by_id):
        for value in usable[fid]:
            buckets.setdefault(value, []).append(fid)

    def neighbors(fid: int) -> Iterator[int]:
        for value in usable.get(fid, ()):
            for other in buckets[value]:
                if other != fid:
                    yield other

    def links_for(members: frozenset[int], targets: Iterable[int]) -> dict[int, tuple[Link, ...]]:
        out: dict[int, tuple[Link, ...]] = {}
        for fid in targets:
            found: list[Link] = []
            for value in usable.get(fid, ()):
                for other in buckets[value]:
                    if other != fid and other in members and len(found) < MAX_LINKS:
                        found.append(Link(value[0], value[1], other))
            out[fid] = tuple(found)
        return out

    def ignored_for(members: frozenset[int]) -> tuple[tuple[str, str, int], ...]:
        seen: dict[SignalValue, int] = {}
        for fid in members:
            node = by_id.get(fid)
            if node is None:
                continue
            for value in node.signals:
                if value[0] in enabled and counts.get(value, 0) > max_share:
                    seen[value] = counts[value]
        ordered = sorted(seen.items(), key=lambda item: (-item[1], _order(item[0])))
        return tuple((k, v, n) for (k, v), n in ordered[:MAX_IGNORED])

    owner: dict[int, int] = {}
    for c in confirmed:
        for fid in c.members:
            owner.setdefault(fid, c.campaign_id)

    extensions: dict[int, Group] = {}
    for c in sorted(confirmed, key=lambda c: c.campaign_id):
        start = sorted(fid for fid in c.members if owner.get(fid) == c.campaign_id)
        seen = set(start)
        queue = deque(start)
        added: list[int] = []
        while queue:
            for other in neighbors(queue.popleft()):
                if other in seen or other in c.excluded:
                    continue
                if owner.get(other, c.campaign_id) != c.campaign_id:
                    continue  # 不穿过其他已确认活动的成员
                seen.add(other)
                if other not in owner:
                    owner[other] = c.campaign_id
                    added.append(other)
                queue.append(other)
        members = frozenset(c.members) | frozenset(added)
        extensions[c.campaign_id] = Group(
            tuple(sorted(added)), links_for(members, added), ignored_for(members)
        )

    candidates: list[Group] = []
    visited: set[int] = set()
    for start_id in sorted(by_id):
        if start_id in owner or start_id in visited:
            continue
        component: list[int] = []
        queue = deque([start_id])
        visited.add(start_id)
        while queue:
            current = queue.popleft()
            component.append(current)
            for other in neighbors(current):
                if other not in owner and other not in visited:
                    visited.add(other)
                    queue.append(other)
        if len(component) >= min_members and any(by_id[f].active for f in component):
            members = frozenset(component)
            candidates.append(
                Group(
                    tuple(sorted(component)),
                    links_for(members, sorted(component)),
                    ignored_for(members),
                )
            )
    return Grouping(tuple(candidates), extensions)
