"""Watcher 对照（设计文档 D3、19.1）：解析 Watcher 导出的域名清单，与本平台同期发现比对，互相检查漏报。

导出格式不固定：带表头的 CSV（逗号、分号或制表符分隔，取域名列）、无表头的 CSV（取第一列）或纯文本（每行第一个词）。
"""

from __future__ import annotations

import csv
import io
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from opti.core.config import ProjectRules
from opti.core.domains import normalize_domain, parse_domain

DOMAIN_COLUMNS = ("domain", "domain_name", "dns_domain", "fqdn", "name", "value", "url")


def _host(raw: str) -> str | None:
    value = raw.strip().strip('"').strip()
    if not value:
        return None
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None
    return normalize_domain(value) if value else None


def parse_export(text: str) -> list[str]:
    lines = [
        ln for ln in text.lstrip("﻿").splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not lines:
        return []
    delimiter = next((d for d in (",", ";", "\t") if d in lines[0]), None)
    header = [
        h.strip().strip('"').lower()
        for h in (lines[0].split(delimiter) if delimiter else [lines[0]])
    ]
    column = next((header.index(c) for c in DOMAIN_COLUMNS if c in header), None)
    if delimiter is None:
        values = [ln.split()[0] for ln in (lines[1:] if column is not None else lines)]
    else:
        rows = list(csv.reader(io.StringIO("\n".join(lines)), delimiter=delimiter))
        values = (
            [r[column] for r in rows[1:] if len(r) > column]
            if column is not None
            else [r[0] for r in rows if r]
        )
    return sorted({h for v in values if (h := _host(v))})


def _registered(host: str) -> str:
    parts = parse_domain(host)
    return parts.registered if parts is not None else host


def _protected(host: str, rules: ProjectRules) -> bool:
    for d in (*rules.domains.official, *rules.domains.known_lookalikes):
        base = normalize_domain(d) or d
        if host == base or host.endswith("." + base):
            return True
    return False


@dataclass(frozen=True)
class Comparison:
    both: list[str]
    ours_only: list[str]
    watcher_only: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        missed = sum(w["status"] == "not_found" for w in self.watcher_only)
        return {
            "summary": {"both": len(self.both), "ours_only": len(self.ours_only),
                        "watcher_only": len(self.watcher_only), "missed": missed},
            "both": self.both, "ours_only": self.ours_only, "watcher_only": self.watcher_only,
        }  # fmt: skip


def compare(
    ours: Collection[str],
    theirs: Sequence[str],
    *,
    rules: ProjectRules,
    elsewhere: Collection[str] = frozenset(),
) -> Comparison:
    """同一主机或同一可注册域都算一致；Watcher 独有的按原因分类，只有 not_found 是真正的漏报候选。"""
    our_hosts, our_reg = set(ours), {_registered(h) for h in ours}
    their_set, their_reg = set(theirs), {_registered(h) for h in theirs}
    elsewhere_reg = {_registered(h) for h in elsewhere}
    both = sorted(h for h in their_set if h in our_hosts or _registered(h) in our_reg)
    watcher_only = []
    for h in theirs:
        if h in both:
            continue
        if _protected(h, rules):
            status = "protected"
        elif h in elsewhere or _registered(h) in elsewhere_reg:
            status = "found_outside_window"
        else:
            status = "not_found"
        watcher_only.append({"domain": h, "status": status})
    ours_only = sorted(
        h for h in our_hosts if h not in their_set and _registered(h) not in their_reg
    )
    return Comparison(both, ours_only, watcher_only)
