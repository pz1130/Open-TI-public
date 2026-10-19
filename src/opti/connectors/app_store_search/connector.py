"""在获批的国家商店中搜索公开应用名称和开发者的品牌命中。"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Any, ClassVar

from opti.core.documents import document_payload
from opti.core.feeds import parse_date
from opti.core.text_match import TextMatcher
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

SEARCH_URL = "https://itunes.apple.com/search"
_COUNTRY = re.compile(r"[A-Z]{2}$")


def _app(raw: Any) -> tuple[int, str, str, datetime | None] | None:
    if not isinstance(raw, dict) or raw.get("kind") not in {"software", "software-package"}:
        return None
    app_id = raw.get("trackId")
    if isinstance(app_id, bool) or not isinstance(app_id, int) or not 0 < app_id < 2**63:
        return None
    name = raw.get("trackName")
    developer = raw.get("artistName")
    if not isinstance(name, str) or not isinstance(developer, str):
        return None
    name = " ".join(name.split())[:500]
    developer = " ".join(developer.split())[:300]
    if not name or not developer:
        return None
    return app_id, name, developer, parse_date(raw.get("releaseDate"))


class AppStoreSearchConnector(BaseConnector):
    id: ClassVar[str] = "app_store_search"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        public_sets = {
            name: ts.model_copy(update={"terms": terms})
            for name, ts in ctx.rules.sets.items()
            if ts.type != "executive" and not ts.private
            if (terms := tuple(term for term in ts.terms if term.remote_search))
        }
        self._matcher = TextMatcher(ctx.rules.model_copy(update={"sets": public_sets}))

    def validate_config(self) -> None:
        countries = self.config.get("countries")
        if (
            not isinstance(countries, list)
            or not countries
            or len(countries) > 5
            or any(not isinstance(c, str) or not _COUNTRY.fullmatch(c) for c in countries)
        ):
            raise ValueError("App Store countries 需要 1–5 个经审核的两位大写国家代码")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        seen: set[int] = set()
        queries = list(
            dict.fromkeys(term.value for term in plan.terms if 1 < len(term.value) <= 100)
        )
        for country in self.config.get("countries") or []:
            if not isinstance(country, str) or not _COUNTRY.fullmatch(country):
                continue
            for query in queries[: int(self.config.get("max_queries", 5))]:
                try:
                    response = await self.ctx.http().get(
                        SEARCH_URL,
                        params={
                            "term": query,
                            "country": country,
                            "media": "software",
                            "entity": "software",
                            "limit": str(self.config.get("max_results", 50)),
                        },
                        follow_redirects=False,
                        max_retries=0,
                        max_body_bytes=2 * 1024 * 1024,
                    )
                    if response.status_code != 200:
                        raise ValueError("App Store 搜索返回非成功状态")
                    data = response.json()
                    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                        raise ValueError("App Store 搜索响应格式不正确")
                except (HttpError, ValueError) as exc:
                    self.ctx.logger().warning("App Store 搜索失败：%s", type(exc).__name__)
                    continue
                for raw in data["results"]:
                    parsed = _app(raw)
                    if parsed is None:
                        continue
                    app_id, name, developer, published = parsed
                    if app_id in seen:
                        continue
                    body = f"{name}\n开发者：{developer}"
                    if not any(hit.role == "match" for hit in self._matcher.match(body)):
                        continue
                    seen.add(app_id)
                    url = f"https://apps.apple.com/app/id{app_id}"
                    yield RawItem(
                        connector_id=self.id,
                        source_item_id=f"app:{app_id}",
                        fetched_at=utcnow(),
                        url=url,
                        payload=document_payload(
                            url=url,
                            title="App Store 应用候选",
                            text=body,
                            published_at=published,
                            source_name=f"Apple App Store · {country}",
                        ),
                        project_ids=plan.project_ids,
                    )
