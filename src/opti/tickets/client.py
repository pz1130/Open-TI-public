"""工单客户端（设计文档 12、15）：通用 Webhook（HMAC 签名）或邮件；回调验签。

签名：hex(HMAC-SHA256(key, f"{ts}.".encode() + body))，ts 为 Unix 秒，放在 X-Opti-Timestamp；与 S2-B 对外入口一致。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from typing import Any, Protocol

from opti.alerting.config import AlertingConfig
from opti.alerting.email import SendFn, smtp_sender
from opti.alerting.views import CATEGORY_LABEL, SEVERITY_LABEL, AlertView, defang
from opti.core.secret_guard import mask_deep, mask_text
from opti.sdk.http import RateLimitedHttpClient
from opti.tickets.config import TicketsConfig
from opti.tickets.remote import HttpFactory
from opti.tickets.remote import http_factory as remote_http_factory

log = logging.getLogger("opti.tickets")
SIGNATURE_HEADER = "X-Opti-Signature"
TIMESTAMP_HEADER = "X-Opti-Timestamp"
MAX_SKEW_SECONDS = 300
MIN_KEY_LENGTH = 32
TICKET_REF_PATTERN = r"^[A-Za-z0-9._#/:-]{1,100}$"
_REF = re.compile(TICKET_REF_PATTERN)


class SignatureError(Exception):
    pass


def sign(key: bytes, ts: int, body: bytes) -> str:
    return hmac.new(key, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


def verify(
    key: bytes, ts_header: str | None, sig_header: str | None, body: bytes, now: datetime
) -> int:
    if not ts_header or not re.fullmatch(r"[0-9]{1,12}", ts_header):
        raise SignatureError("invalid timestamp")
    if not sig_header or not re.fullmatch(r"[0-9a-f]{64}", sig_header):
        raise SignatureError("invalid signature")
    try:
        ts = int(ts_header or "")
    except ValueError as e:
        raise SignatureError("missing or invalid timestamp") from e
    if abs(now.timestamp() - ts) > MAX_SKEW_SECONDS:
        raise SignatureError("timestamp outside the allowed window")
    if not hmac.compare_digest(sign(key, ts, body), sig_header or ""):
        raise SignatureError("bad signature")
    return ts


def clean_ref(value: Any) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v if _REF.fullmatch(v) else None


def ticket_payload(
    view: AlertView, extra: Mapping[str, Any] | None = None, *, idempotency_key: str | None = None
) -> dict[str, Any]:
    payload = {
        "event": "alert.ticket",
        "idempotency_key": idempotency_key or f"opti-alert-{view.alert_id}",
        "alert_id": view.alert_id,
        "project_id": view.project_id,
        "severity": view.severity,
        "category": view.category,
        "domain": defang(view.domain),  # 工单系统可能自动生成链接：去链接化
        "score": view.score,
        "reasons": list(view.reasons),
        "first_seen": view.first_seen.isoformat(),
        "created_at": view.created_at.isoformat(),
        "link": view.link,
    }
    if extra:
        payload["details"] = dict(extra)
    masked: dict[str, Any] = mask_deep(payload)
    return masked


@dataclass(frozen=True)
class PushResult:
    ref: str | None  # 工单编号；邮件方式或对方未返回时为 None（等回调或人工填写）
    channel: str


class TicketClient(Protocol):
    """existing_ref：告警已有工单时的编号。Jira / ServiceNow 据此追加评论，Webhook 与邮件忽略。"""

    @property
    def name(self) -> str: ...

    async def push(
        self,
        view: AlertView,
        extra: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult: ...


def _dig(doc: Any, path: str) -> Any:
    for part in path.split("."):
        doc = doc.get(part) if isinstance(doc, dict) else None
    return doc


class WebhookTicketClient:
    name = "webhook"

    def __init__(
        self,
        http: RateLimitedHttpClient,
        url: str,
        key: bytes,
        id_field: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._http, self._url, self._key, self._id_field, self._clock = (
            http,
            url,
            key,
            id_field,
            clock,
        )

    async def push(
        self,
        view: AlertView,
        extra: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        body = json.dumps(
            ticket_payload(view, extra, idempotency_key=idempotency_key),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        ts = int(self._clock())
        headers = {
            "Content-Type": "application/json",
            TIMESTAMP_HEADER: str(ts),
            SIGNATURE_HEADER: sign(self._key, ts, body),
            "Idempotency-Key": idempotency_key or f"opti-alert-{view.alert_id}",
        }
        resp = await self._http.post_bytes(self._url, body, headers=headers)
        if not 200 <= resp.status_code < 300:
            from opti.sdk.http import HttpError

            raise HttpError(self._url, resp.status_code, "ticket webhook did not accept payload")
        try:
            doc = resp.json()
        except ValueError:
            doc = None
        return PushResult(clean_ref(_dig(doc, self._id_field)), self.name)


class EmailTicketClient:
    name = "email"

    def __init__(self, send: SendFn, sender: str, to: Sequence[str]) -> None:
        self._send, self._sender, self._to = send, sender, list(to)

    async def push(
        self,
        view: AlertView,
        extra: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        severity = SEVERITY_LABEL.get(view.severity, view.severity)
        category = CATEGORY_LABEL.get(view.category, view.category)
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._to)
        msg["Subject"] = (
            f"[OPTI-ALERT-{view.alert_id}] [{severity}] {category}：{defang(view.domain)}"
        )
        msg.set_content(
            mask_text(
                f"告警编号：{view.alert_id}\n级别：{severity}\n类别：{category}\n域名 / URL：{defang(view.domain)}\n"
                f"评分：{view.score}\n命中原因：{'、'.join(view.reasons) or '-'}\n首次发现：{view.first_seen.isoformat()}\n"
                f"在平台中查看：{view.link}\n\n机器可读：{json.dumps(ticket_payload(view, extra, idempotency_key=idempotency_key), ensure_ascii=False)}\n"
                + (
                    f"\n附加信息：\n{json.dumps(dict(extra), ensure_ascii=False, indent=2)}\n"
                    if extra
                    else ""
                )
            )
        )
        await self._send(msg)
        return PushResult(None, self.name)


def build_ticket_client(
    cfg: TicketsConfig,
    alerting: AlertingConfig,
    http: RateLimitedHttpClient,
    *,
    webhook_url: str | None = None,
    signing_key: str | None = None,
    smtp_auth: tuple[str | None, str | None] = (None, None),
    secrets: Mapping[str, str | None] | None = None,
    http_factory: HttpFactory | None = None,
) -> TicketClient | None:
    """secrets：jira_api_token / servicenow_password / servicenow_client_secret。
    http_factory：仅 jira / servicenow，默认按 cfg.proxy 新建；测试注入假传输。"""
    if not cfg.enabled:
        return None
    if cfg.mode in ("jira", "servicenow"):
        from opti.tickets.factory import build_remote_client  # jira / servicenow 依赖本模块

        return build_remote_client(
            cfg, secrets or {}, http_factory or remote_http_factory(cfg.proxy)
        )
    if cfg.mode == "email":
        if not cfg.email_to:
            log.warning("工单邮件方式已启用，但收件人为空")
            return None
        sender = smtp_sender(alerting.smtp, *smtp_auth)
        return EmailTicketClient(sender, alerting.smtp.sender, cfg.email_to)
    key = signing_key.encode() if signing_key and len(signing_key) >= MIN_KEY_LENGTH else None
    if not webhook_url or key is None:
        log.warning(
            "工单 Webhook 已启用，但未设置 Webhook 地址或签名密钥（至少 %d 个字符）",
            MIN_KEY_LENGTH,
        )
        return None
    return WebhookTicketClient(http, webhook_url, key, cfg.id_field)
