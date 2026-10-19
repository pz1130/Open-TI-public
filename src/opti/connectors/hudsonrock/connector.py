"""Hudson Rock 统计适配器；接口版本与字段须经授权后核对，默认关闭。"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from opti.core.exposure import exposure_payload, monitored_domains
from opti.sdk.base import BaseConnector
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
# 原计划的 v2 URL/响应字段尚无官方文档佐证；授权后在测试环境核对。
FIELDS = {
    "employees": "employees",
    "users": "users",
    "third_parties": "third_parties",
    "total": "total",
    "last_employee": "last_employee_compromised",
}


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


class HudsonRockConnector(BaseConnector):
    id: ClassVar[str] = "hudsonrock"
    tier: ClassVar[Tier] = Tier.PAID

    def validate_config(self) -> None:
        if not self.config.get("schema_verified") or not self.config.get("api_url"):
            raise ValueError("Hudson Rock API 尚未核对授权、接口地址及响应格式")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        api = str(self.config["api_url"])
        for domain in monitored_domains(
            self.ctx.rules.domains.official, self.config.get("domains") or []
        ):
            try:
                doc = (await self.ctx.http().get(api, params={"domain": domain})).json()
            except (HttpError, ValueError) as e:
                log.warning("查询 Hudson Rock（%s）失败：%s", domain, e)
                continue
            if not isinstance(doc, dict):
                continue
            employees = _int(doc.get(FIELDS["employees"]))
            last = doc.get(FIELDS["last_employee"])
            last_date = last[:10] if isinstance(last, str) and len(last) >= 10 else None
            state = f"{employees}|{last_date or ''}"
            cursor = f"state:{domain}"
            if self.ctx.get_cursor(cursor) == state:
                continue
            if employees > 0:
                yield RawItem(
                    connector_id=self.id,
                    source_item_id=f"{domain}:{hashlib.sha256(state.encode()).hexdigest()[:16]}",
                    fetched_at=utcnow(),
                    url=None,
                    payload=exposure_payload(
                        source=self.id,
                        kind="stealer",
                        key=f"hudsonrock:{domain}",
                        domain=domain,
                        info=None,
                        title=f"Infostealer infections ({domain})",
                        affected=employees,
                        accounts=[],
                        breach_date=last_date,
                        context={
                            k: _int(doc.get(FIELDS[k])) for k in ("users", "third_parties", "total")
                        },
                    ),
                    project_ids=plan.project_ids,
                )
            self.ctx.set_cursor(cursor, state)
