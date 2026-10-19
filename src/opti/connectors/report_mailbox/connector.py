"""员工钓鱼举报邮箱（设计文档 4.12）：读取举报邮件，提取被举报邮件中的指标。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import replace
from typing import Any, ClassVar
from urllib.parse import urlsplit

from opti.connectors.graphmail import GraphError, GraphMailClient
from opti.core.domains import parse_domain
from opti.core.mailparse import AttachmentInfo, ReportedMessage, parse_eml, parse_graph_message
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

DEFAULT_IGNORE = (
    "microsoft.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "aka.ms",
    "sharepoint.com",
    "w3.org",
    "apple.com",
    "google.com",
    "gstatic.com",
)

MAX_EML_BYTES = 10 * 1024 * 1024


class ReportMailboxConnector(BaseConnector):
    id: ClassVar[str] = "report_mailbox"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._ignore = {d.lower().strip(".") for d in config.get("ignore_domains", DEFAULT_IGNORE)}

    def validate_config(self) -> None:
        for name in ("tenant_id", "client_id", "client_secret"):
            if not self.ctx.secret(name):
                raise MissingCredential(f"需要 {name}（OPTI_SECRET_REPORT_MAILBOX_{name.upper()}）")

    def _graph(self) -> GraphMailClient:
        return GraphMailClient(
            self.ctx.http(),
            tenant_id=self.ctx.secret("tenant_id") or "",
            client_id=self.ctx.secret("client_id") or "",
            client_secret=self.ctx.secret("client_secret") or "",
            authority=str(self.config.get("authority", "https://login.microsoftonline.com")),
            graph=str(self.config.get("graph", "https://graph.microsoft.com/v1.0")),
        )

    def _ignored(self, domain: str | None) -> bool:
        parts = parse_domain(domain or "")
        return parts is None or any(
            parts.fqdn == d or parts.fqdn.endswith("." + d) for d in self._ignore
        )

    async def _originals(
        self, graph: GraphMailClient, mailbox: str, msg: Mapping[str, Any]
    ) -> tuple[list[ReportedMessage], bool]:
        """被举报的原始邮件：.eml 附件、Outlook 项目附件。

        都没有时把举报邮件本身当作"内联转发"解析，第二个返回值为 True。
        """
        found: list[ReportedMessage] = []
        hashes: list[AttachmentInfo] = []
        if msg.get("hasAttachments"):
            for att in await graph.attachments(mailbox, str(msg["id"])):
                kind = str(att.get("@odata.type", ""))
                name = str(att.get("name", "")).lower()
                encoded = str(att.get("contentBytes") or "")
                if len(encoded) > (MAX_EML_BYTES + 2) // 3 * 4:
                    self.ctx.logger().warning("跳过超过附件大小上限的文件")
                    continue
                if kind.endswith("fileAttachment"):
                    try:
                        binary = base64.b64decode(encoded, validate=True)
                    except (binascii.Error, ValueError):
                        continue
                    hashes.append(
                        AttachmentInfo(
                            str(att.get("name", ""))[:200],
                            str(att.get("contentType") or "application/octet-stream"),
                            len(binary),
                            hashlib.sha256(binary).hexdigest(),
                        )
                    )
                if kind.endswith("fileAttachment") and (
                    att.get("contentType") == "message/rfc822" or name.endswith(".eml")
                ):
                    try:
                        data = base64.b64decode(str(att.get("contentBytes") or ""), validate=True)
                    except (binascii.Error, ValueError):
                        continue
                    if len(data) <= MAX_EML_BYTES:
                        found.append(parse_eml(data))
                elif kind.endswith("itemAttachment"):
                    expanded = await graph.item_attachment(
                        mailbox, str(msg["id"]), str(att.get("id"))
                    )
                    hashes.append(
                        AttachmentInfo(
                            str(att.get("name", ""))[:200],
                            "message/rfc822",
                            len(json.dumps(expanded).encode()),
                            hashlib.sha256(
                                json.dumps(expanded, sort_keys=True).encode()
                            ).hexdigest(),
                        )
                    )
                    item = expanded.get("item")
                    if isinstance(item, Mapping):
                        found.append(parse_graph_message(item))
        if found:
            found[0] = replace(found[0], attachments=(*found[0].attachments, *hashes)[:20])
            return found, False
        inline = parse_graph_message(msg)
        return [replace(inline, attachments=tuple(hashes[:20]))], True

    def _indicators(self, reports: list[ReportedMessage], forwarded: bool) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for r in reports:
            for url in r.urls:
                host = urlsplit(url).hostname or ""
                if not self._ignored(host):
                    out.append({"type": "url", "value": url})
            # 举报邮件本身（无附件时）的发件人是员工，不能当作可疑发件域
            domains = (
                () if forwarded else (r.sender_domain, r.reply_to_domain, r.return_path_domain)
            )
            for d in domains:
                if d and not self._ignored(d):
                    out.append({"type": "domain", "value": d})
        unique: list[dict[str, Any]] = []
        for ind in out:
            if ind not in unique:
                unique.append(ind)
        return unique[:50]

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        mailbox = str(self.config["mailbox"])
        graph = self._graph()
        since = self.ctx.get_cursor("since")
        try:
            messages = await graph.list_messages(
                mailbox,
                str(self.config.get("folder", "Inbox")),
                since=since,
                next_link=self.ctx.get_cursor("next_link") or None,
            )
        except GraphError as e:
            self.ctx.logger().warning("读取举报邮箱失败：%s", e)
            return
        newest = since
        complete = True
        for msg in messages:
            try:
                reports, forwarded = await self._originals(graph, mailbox, msg)
            except GraphError as e:
                self.ctx.logger().warning("读取举报邮件 %s 的附件失败：%s", msg.get("id"), e)
                complete = False
                break  # 不推进游标，下次重试
            first = reports[0]
            yield RawItem(
                connector_id=self.id,
                source_item_id=str(msg["id"]),
                fetched_at=utcnow(),
                url=None,
                payload={
                    "indicators": self._indicators(reports, forwarded),
                    "signal": "reported",
                    "intel": {"source": self.id, "confirmed": False},
                    "context": {
                        "subject": first.subject,
                        "received_at": msg.get("receivedDateTime"),
                        "graph_message_id": msg.get("id"),
                        "internet_message_id": first.message_id,
                        "sender_domain": None if forwarded else first.sender_domain,
                        "attachments": [a.__dict__ for r in reports for a in r.attachments][:20],
                        "auth_results": None if forwarded else first.auth_results,
                    },
                },
                project_ids=plan.project_ids,
            )
            received = msg.get("receivedDateTime")
            if isinstance(received, str) and (not newest or received > newest):
                newest = received
        if not complete:
            return
        self.ctx.set_cursor("next_link", graph.next_link or "")
        if newest and newest != since:
            self.ctx.set_cursor("since", newest)
