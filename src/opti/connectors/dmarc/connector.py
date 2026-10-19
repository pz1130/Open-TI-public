"""DMARC 聚合报告（设计文档 4.5）：发现冒用本机构域名发件的来源 IP。"""

from __future__ import annotations

import base64
import binascii
import ipaddress
from collections import Counter
from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.connectors.graphmail import GraphError, graph_client
from opti.core.dmarc import DmarcError, DmarcReport, parse_report, unpack
from opti.core.domains import normalize_domain
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

REPORT_SUFFIXES = (".xml", ".gz", ".zip")


class DmarcConnector(BaseConnector):
    id: ClassVar[str] = "dmarc"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._official = {d.lower() for d in ctx.rules.domains.official}
        self._authorized = [
            ipaddress.ip_network(n, strict=False) for n in config.get("authorized_networks", [])
        ]

    def validate_config(self) -> None:
        for name in ("tenant_id", "client_id", "client_secret"):
            if not self.ctx.secret(name):
                raise MissingCredential(f"需要 {name}（OPTI_SECRET_DMARC_{name.upper()}）")

    def _own(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        return normalized is not None and any(
            normalized == d or normalized.endswith("." + d) for d in self._official
        )

    def _authorized_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # 无法解析的地址不作为指标
        return not addr.is_global or any(addr in net for net in self._authorized)

    def _item(self, report: DmarcReport, plan: QueryPlan) -> RawItem | None:
        own = [r for r in report.records if self._own(r.header_from or report.domain)]
        if not own:
            return None
        failing = [
            r
            for r in own
            if r.dkim != "pass" and r.spf != "pass" and not self._authorized_ip(r.source_ip)
        ]
        if not failing:
            return None
        volume: Counter[str] = Counter()
        for r in failing:
            volume[r.source_ip] += r.count
        indicators = [
            {"type": "ip", "value": ip, "volume": n}
            for ip, n in sorted(volume.items(), key=lambda kv: (-kv[1], kv[0]))[:50]
        ]
        return RawItem(
            connector_id=self.id,
            source_item_id=f"{report.org_name}:{report.report_id}",
            fetched_at=utcnow(),
            url=None,
            payload={
                "indicators": indicators,
                "signal": "dmarc_fail",
                "intel": {"source": self.id, "confirmed": False},
                "context": {
                    "reporter": report.org_name,
                    "report_id": report.report_id,
                    "domain": report.domain,
                    "date_begin": report.date_begin.isoformat(),
                    "date_end": report.date_end.isoformat(),
                    "total_messages": sum(r.count for r in own),
                    "failing_messages": sum(r.count for r in failing),
                    "failing": [
                        {
                            "ip": r.source_ip,
                            "count": r.count,
                            "header_from": r.header_from,
                            "disposition": r.disposition,
                        }
                        for r in failing[:50]
                    ],
                },
            },
            project_ids=plan.project_ids,
        )

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        mailbox = str(self.config["mailbox"])
        graph = graph_client(self.ctx, self.config)
        since = self.ctx.get_cursor("since")
        try:
            messages = await graph.list_messages(
                mailbox,
                str(self.config.get("folder", "Inbox")),
                since=since,
                next_link=self.ctx.get_cursor("next_link") or None,
            )
        except GraphError as e:
            self.ctx.logger().warning("读取 DMARC 邮箱失败：%s", e)
            return
        newest = since
        complete = True
        for msg in messages:
            if msg.get("hasAttachments"):
                try:
                    attachments = await graph.attachments(mailbox, str(msg["id"]))
                except GraphError as e:
                    self.ctx.logger().warning("读取 DMARC 报告附件失败：%s", e)
                    complete = False
                    break
                for att in attachments:
                    name = str(att.get("name") or "")
                    if not name.lower().endswith(REPORT_SUFFIXES):
                        continue
                    try:
                        encoded = str(att.get("contentBytes") or "")
                        if len(encoded) > 28 * 1024 * 1024:
                            raise DmarcError("压缩附件超过上限")
                        data = base64.b64decode(encoded, validate=True)
                        report = parse_report(unpack(name, data))
                    except (DmarcError, binascii.Error, ValueError) as e:
                        self.ctx.logger().warning("跳过无法解析的 DMARC 报告 %s：%s", name, e)
                        continue
                    item = self._item(report, plan)
                    if item is not None:
                        yield item
            received = msg.get("receivedDateTime")
            if isinstance(received, str) and (not newest or received > newest):
                newest = received
        if not complete:
            return
        self.ctx.set_cursor("next_link", graph.next_link or "")
        if newest and newest != since:
            self.ctx.set_cursor("since", newest)
