"""官网访问日志中的 Referer（设计文档 4.12）：钓鱼工具包常直接盗链官网的 Logo、样式与脚本。

只保留来源主机名、次数与被盗用的资源路径；不保存访问者 IP、完整来源 URL 或 User-Agent。
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from opti.core.config import ProjectRules
from opti.core.domains import parse_domain
from opti.sdk.models import RawItem, utcnow

_COMBINED = re.compile(
    r'"(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ "(?P<ref>[^"]*)"'
)
DEFAULT_PROTECTED = r"\.(?:png|jpe?g|gif|svg|webp|ico|css|js|woff2?|ttf)(?:$|\?)"
DEFAULT_IGNORE = (
    "google.com", "bing.com", "baidu.com", "yandex.ru", "duckduckgo.com", "sogou.com", "so.com",
    "facebook.com", "t.co", "x.com", "linkedin.com", "qq.com", "weibo.com", "googleusercontent.com",
)  # fmt: skip
_OK_STATUS = frozenset({200, 206, 304})


@dataclass(frozen=True)
class AccessRecord:
    referer_host: str | None
    path: str
    status: int | None


def _host(referer: object) -> str | None:
    if not isinstance(referer, str) or referer in ("", "-"):
        return None
    try:
        return urlsplit(referer).hostname
    except ValueError:
        return None


def parse_line(line: str) -> AccessRecord | None:
    s = line.strip()
    start = s.find("{")
    if start != -1:
        try:
            d = json.loads(s[start:])
        except ValueError:
            return None
        if not isinstance(d, dict):
            return None
        ref = (
            d.get("http_referer")
            or d.get("referer")
            or d.get("referrer")
            or d.get("ClientRequestReferer")
        )
        path = d.get("request_uri") or d.get("uri") or d.get("path") or d.get("ClientRequestPath")
        status = d.get("status") or d.get("EdgeResponseStatus")
        if not isinstance(path, str):
            return None
        return AccessRecord(_host(ref), path, int(str(status)) if str(status).isdigit() else None)
    m = _COMBINED.search(s)
    if m is None:
        return None
    return AccessRecord(_host(m.group("ref")), m.group("path"), int(m.group("status")))


@dataclass
class _Window:
    start: float
    hits: int = 0
    assets: set[str] = field(default_factory=set)


class RefererAggregator:
    def __init__(
        self,
        rules: ProjectRules,
        *,
        protected: str = DEFAULT_PROTECTED,
        ignore_domains: Iterable[str] = DEFAULT_IGNORE,
        window: float = 3600.0,
        min_hits: int = 3,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._project = rules.project
        self._official = {d.lower() for d in rules.domains.official}
        self._ignore = {d.lower() for d in ignore_domains}
        self._protected = re.compile(protected, re.I)
        self._window = window
        self._min_hits = min_hits
        self._clock = clock
        self._hosts: dict[str, _Window] = {}
        if window <= 0 or min_hits < 1:
            raise ValueError("窗口与最少次数必须大于 0")

    def update_rules(self, rules: ProjectRules) -> None:
        """规则更新：后续记录用新的项目标识与官方域名；已累计的窗口计数保留。"""
        self._project = rules.project
        self._official = {d.lower() for d in rules.domains.official}

    def add(self, rec: AccessRecord | None) -> None:
        if rec is None or rec.referer_host is None:
            return
        if rec.status is not None and rec.status not in _OK_STATUS:
            return
        if not self._protected.search(rec.path):
            return
        parts = parse_domain(rec.referer_host)
        if (
            parts is None
            or any(parts.fqdn == d or parts.fqdn.endswith("." + d) for d in self._official)
            or parts.registered in self._ignore
        ):
            return
        if parts.fqdn not in self._hosts and len(self._hosts) >= 10_000:
            return
        w = self._hosts.setdefault(parts.fqdn, _Window(start=self._clock()))
        w.hits += 1
        if len(w.assets) < 5:
            w.assets.add(rec.path.split("?", 1)[0][:200])

    def flush(self, *, force: bool = False) -> list[RawItem]:
        now = self._clock()
        out: list[RawItem] = []
        for host in sorted(self._hosts):
            w = self._hosts[host]
            if not force and now - w.start < self._window:
                continue
            del self._hosts[host]
            if w.hits < self._min_hits:
                continue
            bucket = time.strftime("%Y%m%d%H", time.gmtime(w.start))
            out.append(
                RawItem(
                    connector_id="referer_log",
                    source_item_id=f"{host}:{bucket}",
                    fetched_at=utcnow(),
                    url=None,
                    payload={
                        "indicators": [{"type": "domain", "value": host, "volume": w.hits}],
                        "signal": "hotlink",
                        "intel": {"source": "referer_log", "confirmed": False},
                        "context": {
                            "hits": w.hits,
                            "assets": sorted(w.assets),
                            "window_start": bucket,
                        },
                    },
                    project_ids=(self._project,),
                )
            )
        return out
