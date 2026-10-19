"""HIBP 免费域名通知邮件（设计文档 4.6）：没有订阅时，解析 HIBP 发到域名验证邮箱的通知。

只得到"某泄露事件涉及本机构域名"与受影响数量，不含账户明细（明细需在 HIBP 后台查看或订阅后用 hibp 连接器）。
邮箱只读（Microsoft Graph Mail.Read，由管理员限定到该邮箱），境内运行。
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.graphmail import GraphError, graph_client
from opti.core.exposure import (
    breach_catalog,
    exposure_payload,
    monitored_domains,
    parse_notification,
)
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://haveibeenpwned.com/api/v3"
DEFAULT_SENDERS = ("noreply@haveibeenpwned.com",)


class HibpNotifyConnector(BaseConnector):
    id: ClassVar[str] = "hibp_notify"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._senders = [str(s) for s in config.get("senders") or DEFAULT_SENDERS]

    def validate_config(self) -> None:
        for name in ("tenant_id", "client_id", "client_secret"):
            if not self.ctx.secret(name):
                raise MissingCredential(f"需要 {name}（OPTI_SECRET_HIBP_NOTIFY_{name.upper()}）")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        mailbox = str(self.config["mailbox"])
        graph = graph_client(self.ctx, self.config)
        since = self.ctx.get_cursor("since")
        try:
            messages = await graph.list_messages(
                mailbox, str(self.config.get("folder", "Inbox")), since=since,
                next_link=self.ctx.get_cursor("next_link") or None,
            )  # fmt: skip
            api = str(self.config.get("api_base", API)).rstrip("/")
            catalog = breach_catalog((await self.ctx.http().get(f"{api}/breaches")).json())
        except (GraphError, HttpError, ValueError) as e:
            log.warning("读取 HIBP 通知失败：%s", e)
            return
        domains = monitored_domains(
            self.ctx.rules.domains.official, self.config.get("domains") or []
        )
        newest = since
        for msg in messages:
            note = parse_notification(
                msg, senders=self._senders, domains=domains, catalog=catalog,
                require_dmarc=bool(self.config.get("require_dmarc_pass", True)),
            )  # fmt: skip
            for info in note.breaches if note is not None else ():
                assert note is not None  # 供类型检查：循环只在 note 存在时执行
                yield RawItem(
                    connector_id=self.id,
                    source_item_id=f"{msg.get('id')}:{note.domain}:{info.name}",
                    fetched_at=utcnow(),
                    url=None,
                    payload=exposure_payload(
                        source=self.id,
                        kind="breach",
                        key=f"hibp:{note.domain}:{info.name}",
                        domain=note.domain,
                        info=info,
                        title=info.title,
                        affected=note.affected,
                        accounts=[],
                    ),
                    project_ids=plan.project_ids,
                )
            received = msg.get("receivedDateTime")
            if isinstance(received, str) and (not newest or received > newest):
                newest = received
        self.ctx.set_cursor("next_link", graph.next_link or "")
        if newest and newest != since:
            self.ctx.set_cursor("since", newest)
