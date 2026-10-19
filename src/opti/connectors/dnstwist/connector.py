"""dnstwist 仿冒域名生成（设计文档 4.5、7.3）：本地生成候选 → 匹配器过滤 → DNS 检查是否已注册。"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

import dnstwist

from opti.core.domain_match import DomainMatcher
from opti.enrichers.dns.resolver import DnspythonResolver, DnsRecords, DnsResolver
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow


class DnstwistConnector(BaseConnector):
    id: ClassVar[str] = "dnstwist"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(
        self,
        ctx: ConnectorContext,
        config: Mapping[str, Any],
        *,
        resolver: DnsResolver | None = None,
    ) -> None:
        super().__init__(ctx, config)
        rules = ctx.rules.domains
        self._matcher = DomainMatcher(rules)
        self._short_max = rules.short_token_max_len
        self._affixes = tuple(dict.fromkeys((*rules.combo_affixes, *rules.fraud_affixes)))
        self._resolver = resolver or DnspythonResolver(
            nameservers=self.config.get("nameservers") or None
        )

    def _labels_for(self, token: str) -> set[str]:
        long = len(token) > self._short_max
        fuzzers = list(self.config.get("long_token_fuzzers" if long else "short_token_fuzzers", []))
        fuzzer = dnstwist.Fuzzer(f"{token}.com")
        fuzzer.generate(fuzzers=fuzzers)
        labels = {
            str(d["domain"])[: -len(".com")]
            for d in fuzzer.domains
            if str(d["domain"]).endswith(".com")
        }
        labels = {x for x in labels if x and "." not in x}
        labels.add(token)
        if not long:
            for a in self._affixes:
                labels |= {f"{token}{a}", f"{token}-{a}", f"{a}{token}", f"{a}-{token}"}
        return labels

    def candidates(self, plan: QueryPlan) -> list[str]:
        tlds = list(self.config.get("tlds") or ["com"])
        groups: dict[str, list[str]] = {}
        seen: set[str] = set()
        for raw in plan.brand_tokens:
            token = raw.replace("-", "")
            found: set[str] = set()
            for label in self._labels_for(token):
                for tld in tlds:
                    m = self._matcher.match(f"{label}.{tld}")
                    if m is not None and m.status == "match" and m.domain not in seen:
                        found.add(m.domain)
            seen |= found
            groups[token] = sorted(found)
        limit = int(self.config.get("max_candidates", 50000))
        total = sum(len(g) for g in groups.values())
        if total <= limit:
            return sorted(seen)
        self.ctx.logger().warning("候选域名 %d 个，超过上限 %d，已截断", total, limit)
        return sorted(self._cap(groups, limit))

    def _cap(self, groups: dict[str, list[str]], limit: int) -> list[str]:
        """截断时先保留短品牌词（主品牌，候选少）的全部候选，剩余名额由长品牌词轮流分配。

        v0.1 计划按字母顺序截断，会让 b 开头的 某个长品牌词的变体占满名额、丢掉短品牌词的候选。
        """
        short = [t for t in groups if len(t) <= self._short_max]
        chosen: list[str] = [d for t in sorted(short) for d in groups[t]][:limit]
        queues = [deque(groups[t]) for t in sorted(groups) if t not in short]
        while len(chosen) < limit and any(queues):
            for q in queues:
                if q and len(chosen) < limit:
                    chosen.append(q.popleft())
        return chosen

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        sem = asyncio.Semaphore(int(self.config.get("concurrency", 50)))

        async def check(domain: str) -> tuple[str, DnsRecords] | None:
            async with sem:
                if await self._resolver.is_registered(domain) is True:
                    return domain, await self._resolver.lookup(domain)
                return None

        tasks = [asyncio.create_task(check(d)) for d in self.candidates(plan)]
        try:
            for fut in asyncio.as_completed(tasks):
                result = await fut
                if result is None:
                    continue
                domain, records = result
                m = self._matcher.match(domain)
                if m is None:
                    continue
                yield RawItem(
                    connector_id=self.id,
                    source_item_id=domain,
                    fetched_at=utcnow(),
                    url=None,
                    payload={
                        "domain": domain,
                        "dns": records.to_dict(),
                        "matches": [m.to_dict()],
                    },
                    project_ids=plan.project_ids,
                )
        finally:
            for t in tasks:
                t.cancel()
