"""邮件推送（SMTP，经使用机构邮件中继，设计文档 13）。"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from collections.abc import Awaitable, Callable, Sequence
from email.message import EmailMessage

from opti.alerting.config import SmtpServer
from opti.alerting.views import CATEGORY_LABEL, SEVERITY_LABEL, AlertView, Notice, defang
from opti.core.reports import ReportView
from opti.core.secret_guard import mask_text

SendFn = Callable[[EmailMessage], Awaitable[None]]


def _message(smtp: SmtpServer, recipients: Sequence[str], subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = smtp.sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = mask_text(subject)
    msg.set_content(mask_text(body))
    return msg


def build_alert_email(view: AlertView, smtp: SmtpServer, recipients: Sequence[str]) -> EmailMessage:
    severity = SEVERITY_LABEL.get(view.severity, view.severity)
    category = CATEGORY_LABEL.get(view.category, view.category)
    body = (
        f"类别：{category}\n域名：{defang(view.domain)}\n评分：{view.score}\n"
        f"命中原因：{'、'.join(view.reasons) or '-'}\n首次发现：{view.first_seen.isoformat()}\n\n"
        f"在平台中查看：{view.link}\n"
    )
    return _message(smtp, recipients, f"[{severity}] {category}：{defang(view.domain)}", body)


def build_report_email(
    report: ReportView, smtp: SmtpServer, recipients: Sequence[str]
) -> EmailMessage:
    msg = _message(smtp, recipients, report.title, report.text)
    msg.add_alternative(report.html, subtype="html")
    return msg


def smtp_sender(smtp: SmtpServer, username: str | None, password: str | None) -> SendFn:
    def send_sync(msg: EmailMessage) -> None:
        with smtplib.SMTP(smtp.host, smtp.port, timeout=30) as client:
            if smtp.starttls:
                client.starttls(context=ssl.create_default_context())
            if username:
                client.login(username, password or "")
            client.send_message(msg)

    async def send(msg: EmailMessage) -> None:
        await asyncio.to_thread(send_sync, msg)

    return send


class EmailSink:
    def __init__(
        self, name: str, smtp: SmtpServer, recipients: Sequence[str], send: SendFn
    ) -> None:
        self.name = name
        self._smtp = smtp
        self._recipients = tuple(recipients)
        self._send = send

    async def send_alert(self, view: AlertView) -> None:
        await self._send(build_alert_email(view, self._smtp, self._recipients))

    async def send_report(self, report: ReportView) -> None:
        await self._send(build_report_email(report, self._smtp, self._recipients))

    async def send_notice(self, notice: Notice) -> None:
        await self._send(build_notice_email(notice, self._smtp, self._recipients))


def build_notice_email(notice: Notice, smtp: SmtpServer, recipients: Sequence[str]) -> EmailMessage:
    body = "\n".join(f"{k}：{v}" for k, v in notice.facts) + f"\n\n在平台中查看：{notice.link}\n"
    return _message(smtp, recipients, notice.title, body)
