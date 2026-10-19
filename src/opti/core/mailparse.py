"""举报邮件解析（设计文档 4.12）：只提取指标（链接、发件域、附件哈希、认证结果），不保存正文。纯逻辑，不联网。

附件只计算 SHA-256，绝不解压、打开或保存（设计文档 2.3、4.12）。
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.message import Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlsplit

from opti.core.domains import normalize_domain
from opti.core.urls import normalize_url

SUBJECT_MAX = 200
AUTH_MAX = 500
_URL = re.compile(r"(?:https?|hxxps?)://[^\s<>\"'()\[\]{}]+(?:\[\.\][^\s<>\"'()\[\]{}]*)*", re.I)
_TRAILING = ".,;:!?。，；：！？）)】]"


@dataclass(frozen=True)
class AttachmentInfo:
    name: str
    content_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ReportedMessage:
    subject: str
    sender_domain: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    urls: tuple[str, ...]
    attachments: tuple[AttachmentInfo, ...]
    auth_results: str | None
    message_id: str | None


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _refang(s: str) -> str:
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    return s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def _unwrap(url: str) -> str:
    """Microsoft Defender Safe Links 把链接包装成 *.safelinks.protection.outlook.com/?url=…。"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if (parts.hostname or "").endswith(".safelinks.protection.outlook.com"):
        inner = parse_qs(parts.query).get("url")
        if inner:
            return inner[0]
    return url


def extract_urls(text: str, *, html: bool = False, limit: int = 100) -> list[str]:
    candidates: list[str] = []
    if html:
        p = _Links()
        try:
            p.feed(text)
        except Exception:  # 畸形 HTML：退回纯文本提取
            p.links, p.text = [], [text]
        candidates.extend(p.links)
        text = " ".join(p.text)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    candidates.extend(m.group(0) for m in _URL.finditer(text))
    out: list[str] = []
    for raw in candidates:
        raw = _refang(raw.strip()).rstrip(_TRAILING)
        if not re.match(r"^(?:https?|hxxps?)://", raw, re.I):
            continue  # mailto:、cid:、data: 等
        url = normalize_url(_unwrap(_refang(raw)))
        if url is not None and url not in out:
            out.append(url)
            if len(out) >= limit:
                break
    return out


def _domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return normalize_domain(address.rsplit("@", 1)[1].strip(" <>"))


def _hash_part(part: Message) -> AttachmentInfo:
    payload = part.get_payload(decode=True)
    data = payload if isinstance(payload, bytes) else b""
    return AttachmentInfo(
        name=str(part.get_filename() or "")[:200],
        content_type=part.get_content_type(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def parse_eml(data: bytes) -> ReportedMessage:
    try:
        msg = message_from_bytes(data, policy=policy.default)
    except Exception:
        return ReportedMessage("", None, None, None, (), (), None, None)
    urls: list[str] = []
    attachments: list[AttachmentInfo] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        ctype = part.get_content_type()
        if disposition == "attachment" or part.get_filename():
            attachments.append(_hash_part(part))
        elif ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                continue
            for u in extract_urls(str(content), html=ctype == "text/html"):
                if u not in urls:
                    urls.append(u)
    reply = getaddresses([str(msg.get("Reply-To") or "")])
    auth = msg.get("Authentication-Results")
    return ReportedMessage(
        subject=str(msg.get("Subject") or "")[:SUBJECT_MAX],
        sender_domain=_domain(parseaddr(str(msg.get("From") or ""))[1]),
        reply_to_domain=_domain(reply[0][1]) if reply else None,
        return_path_domain=_domain(parseaddr(str(msg.get("Return-Path") or ""))[1]),
        urls=tuple(urls[:100]),
        attachments=tuple(attachments[:50]),
        auth_results=str(auth)[:AUTH_MAX] if auth else None,
        message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
    )


def _address(entry: Any) -> str | None:
    if isinstance(entry, Mapping):
        address = entry.get("emailAddress")
        addr = address.get("address") if isinstance(address, Mapping) else None
        return str(addr) if addr else None
    return None


def parse_graph_message(msg: Mapping[str, Any]) -> ReportedMessage:
    headers = {
        str(h.get("name", "")).lower(): str(h.get("value", ""))
        for h in msg.get("internetMessageHeaders") or []
        if isinstance(h, Mapping)
    }
    body = msg.get("body") or {}
    content = str(body.get("content") or "") if isinstance(body, Mapping) else ""
    is_html = isinstance(body, Mapping) and str(body.get("contentType", "")).lower() == "html"
    reply = msg.get("replyTo") or []
    if not isinstance(reply, list):
        reply = []
    return ReportedMessage(
        subject=str(msg.get("subject") or "")[:SUBJECT_MAX],
        sender_domain=_domain(_address(msg.get("from"))),
        reply_to_domain=_domain(_address(reply[0])) if reply else None,
        return_path_domain=_domain(parseaddr(headers.get("return-path", ""))[1]),
        urls=tuple(extract_urls(content, html=is_html)),
        attachments=(),
        auth_results=headers.get("authentication-results", "")[:AUTH_MAX] or None,
        message_id=str(msg.get("internetMessageId")) if msg.get("internetMessageId") else None,
    )
