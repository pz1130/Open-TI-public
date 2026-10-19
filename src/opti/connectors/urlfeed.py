"""钓鱼情报源的公共扫描器（设计文档 4.5）：预过滤 → URL 匹配 → 只回传命中的 URL。

情报源每次下发成千上万条 URL，绝大多数与使用机构无关；只有命中的才变成 RawItem，载荷格式见 S2-A Task 4。
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import quote, urlsplit

from opti.core.config import ProjectRules
from opti.core.urls import UrlMatcher, normalize_url
from opti.sdk.models import QueryPlan, RawItem, utcnow


class UrlFeedScanner:
    def __init__(self, connector_id: str, rules: ProjectRules) -> None:
        self._connector_id = connector_id
        self._matcher = UrlMatcher(rules)
        self.reset()

    def reset(self) -> None:
        """每次 fetch 开始清零；同次运行内多个列表共用去重状态。"""
        self._emitted: set[str] = set()
        self.stats = {"seen": 0, "matched": 0, "invalid": 0}

    def scan(
        self, entries: Iterable[tuple[str, Mapping[str, Any]]], plan: QueryPlan
    ) -> Iterator[RawItem]:
        for raw, intel in entries:
            self.stats["seen"] += 1
            raw = raw.strip()
            if not raw or not self._matcher.could_match(raw):
                if raw and normalize_url(raw) is None:
                    self.stats["invalid"] += 1
                continue
            m = self._matcher.match(raw)
            if m is None:
                self.stats["invalid"] += 1
                continue
            if m.kind is None or m.url in self._emitted:
                continue
            self._emitted.add(m.url)
            self.stats["matched"] += 1
            payload = {
                "feed_url": m.url,
                "kind": m.kind,
                "intel": {**dict(intel), "source": self._connector_id},
                "match": m.to_dict(),
            }
            userinfo = ".".join(r.segment for r in m.path_reasons if r.where == "userinfo")
            if userinfo:
                target = urlsplit(m.url)
                # Carry only matched brand segments, not original credentials.
                payload["match_input"] = target._replace(
                    netloc=f"{quote(userinfo, safe='')}@{target.netloc}"
                ).geturl()
            yield RawItem(
                connector_id=self._connector_id,
                source_item_id=m.url,
                fetched_at=utcnow(),
                url=m.url,
                payload=payload,
                project_ids=plan.project_ids,
            )
