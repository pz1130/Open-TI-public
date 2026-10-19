"""Have I Been Pwned 域名搜索（设计文档 4.6）：本机构邮箱出现在哪些公开泄露事件中。

只调用三个只读接口（subscribeddomains、breacheddomain、breaches）。返回的是本机构员工的邮箱（个人信息），
因此只在境内运行（egress: domestic）；同一事件的名单没有变化时不再产生数据。
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar
from urllib.parse import quote

from opti.core.exposure import (
    MAX_ACCOUNTS,
    BreachInfo,
    breach_catalog,
    exposure_payload,
    group_by_breach,
    monitored_domains,
)
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://haveibeenpwned.com/api/v3"


class HibpConnector(BaseConnector):
    id: ClassVar[str] = "hibp"
    tier: ClassVar[Tier] = Tier.PAID

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._base = str(config.get("api_base", API)).rstrip("/")

    def validate_config(self) -> None:
        if not self.ctx.secret("api_key"):
            raise MissingCredential("需要 api_key（OPTI_SECRET_HIBP_API_KEY）")

    async def _get(self, path: str, *, key: bool = True) -> Any:
        headers = {"hibp-api-key": self.ctx.secret("api_key") or ""} if key else None
        return (
            await self.ctx.http().get(
                f"{self._base}{path}", headers=headers, follow_redirects=False
            )
        ).json()

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        try:
            subscriptions = await self._get("/subscribeddomains")
            if not isinstance(subscriptions, list):
                raise ValueError("subscribeddomains response is not a list")
            subscribed = {
                str(d.get("DomainName", "")).lower() for d in subscriptions if isinstance(d, dict)
            }
            catalog = breach_catalog(await self._get("/breaches", key=False))
        except (HttpError, ValueError, TypeError) as e:
            log.warning("HIBP 接口不可用：%s", e)
            return
        for domain in monitored_domains(
            self.ctx.rules.domains.official, self.config.get("domains") or []
        ):
            if domain not in subscribed:
                log.warning("域名 %s 尚未在 HIBP 后台验证（或订阅不含该域名），跳过", domain)
                continue
            try:
                data = await self._get(f"/breacheddomain/{quote(domain, safe='')}")
            except HttpError as e:
                if e.status != 404:  # 404 表示没有任何泄露
                    log.warning("查询 %s 的泄露事件失败：%s", domain, e)
                continue
            except ValueError:
                log.warning("HIBP 返回了无法解析的结果（%s）", domain)
                continue
            for name, emails in group_by_breach(data, domain).items():
                digest = hashlib.sha256("\n".join(emails).encode()).hexdigest()
                cursor = f"seen:{domain}:{name}"
                if self.ctx.get_cursor(cursor) == digest:
                    continue
                info = catalog.get(name) or BreachInfo.unknown(name)
                for start in range(0, len(emails), MAX_ACCOUNTS):
                    yield RawItem(
                        connector_id=self.id,
                        source_item_id=f"{domain}:{name}:{digest[:16]}:{start}",
                        fetched_at=utcnow(),
                        url=None,
                        payload=exposure_payload(
                            source=self.id,
                            kind="breach",
                            key=f"hibp:{domain}:{name}",
                            domain=domain,
                            info=info,
                            title=info.title,
                            affected=len(emails),
                            accounts=emails[start : start + MAX_ACCOUNTS],
                        ),
                        project_ids=plan.project_ids,
                    )
                self.ctx.set_cursor(cursor, digest)  # 交给流水线之后再记下，失败时下次重发
