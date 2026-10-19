"""crt.sh 历史证书检索（设计文档 4.5）：CT 实时流的补充，用于回溯与补漏。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.core.domain_match import DomainMatch, DomainMatcher
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API_URL = "https://crt.sh/"


class CrtshConnector(BaseConnector):
    id: ClassVar[str] = "crtsh"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._matcher = DomainMatcher(ctx.rules.domains)
        self._short_max = ctx.rules.domains.short_token_max_len

    def compile_queries(self, plan: QueryPlan) -> list[str]:
        out: list[str] = []
        for raw in plan.brand_tokens:
            t = raw.replace("-", "")
            if not t:
                continue
            if len(t) <= self._short_max:
                # 短词不能用 %t%（会匹配 sandbox 等海量无关证书），只查标签开头/结尾
                out += [f"{t}%", f"%.{t}%", f"%-{t}%", f"%{t}.%"]
            else:
                out.append(f"%{t}%")
        # 受限品牌词单独出现太常见（exorbitant），只查与词缀的组合；命中仍由 DomainMatcher 判定
        for raw, affixes in plan.restricted_tokens:
            t = raw.replace("-", "")
            if not t:
                continue
            for affix in affixes:
                a = affix.replace("-", "")
                if not a:
                    continue
                out += [f"%{t}%{a}%", f"%{a}%{t}%"]
        return list(dict.fromkeys(out))

    async def _query(self, q: str) -> list[dict[str, Any]] | None:
        try:
            resp = await self.ctx.http().get(
                str(self.config.get("api_url", API_URL)),
                params={"q": q, "output": "json", "exclude": "expired"},
            )
            data = resp.json()
        except (HttpError, ValueError) as e:
            self.ctx.logger().warning("crt.sh 查询失败，跳过：%s（%s）", q, e)
            return None
        if not isinstance(data, list):
            return None
        return [x for x in data if isinstance(x, dict)]

    def _matches(self, entry: Mapping[str, Any]) -> list[DomainMatch]:
        names = {n.strip() for n in str(entry.get("name_value") or "").splitlines()}
        names.add(str(entry.get("common_name") or "").strip())
        found: dict[str, DomainMatch] = {}
        for n in sorted(x for x in names if x):
            if not self._matcher.could_match(n):
                continue
            m = self._matcher.match(n)
            if m is not None and m.status == "match":
                found.setdefault(m.domain, m)
        return list(found.values())

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        emitted: set[int] = set()
        for q in self.compile_queries(plan):
            entries = await self._query(q)
            if entries is None:
                continue
            key = f"max_id:{q}"
            last = int(self.ctx.get_cursor(key) or 0)
            newest = last
            for e in entries:
                cid = e.get("id")
                if not isinstance(cid, int) or cid <= last:
                    continue
                newest = max(newest, cid)
                if cid in emitted:
                    continue
                emitted.add(cid)
                matches = self._matches(e)
                if not matches:
                    continue
                yield RawItem(
                    connector_id=self.id,
                    source_item_id=str(cid),
                    fetched_at=utcnow(),
                    url=f"https://crt.sh/?id={cid}",
                    payload={
                        "crtsh_id": cid,
                        "issuer_name": e.get("issuer_name"),
                        "not_before": e.get("not_before"),
                        "not_after": e.get("not_after"),
                        "entry_timestamp": e.get("entry_timestamp"),
                        "query": q,
                        "matches": [m.to_dict() for m in matches],
                    },
                    project_ids=plan.project_ids,
                )
            if newest > last:
                self.ctx.set_cursor(key, str(newest))
