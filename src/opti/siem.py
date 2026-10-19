"""SIEM 推送渠道（设计文档 12）：Syslog（CEF，TCP / TLS / UDP）与 JSON Webhook（HMAC 签名，可配成 Splunk HEC）。"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from opti import __version__
from opti.core.secret_guard import mask_deep
from opti.core.siem import SiemEvent, cef, hec_payload, octet_framed, syslog_frame
from opti.sdk.http import HttpError, RateLimitedHttpClient
from opti.sharing import SiemSettings, SyslogChannel, WebhookChannel
from opti.tickets.client import MIN_KEY_LENGTH, SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

TIMEOUT = 10.0
MAX_UDP = 8192
log = logging.getLogger("opti.siem")


class Sender(Protocol):
    name: str

    async def send(self, events: Sequence[SiemEvent]) -> list[int]: ...  # 返回已送达的告警 ID


class SyslogSender:
    name = "syslog"

    def __init__(
        self,
        cfg: SyslogChannel,
        *,
        hostname: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._cfg, self._clock = cfg, clock
        self._hostname = hostname or socket.gethostname()

    def ssl_context(self) -> ssl.SSLContext | None:
        if self._cfg.protocol != "tls":
            return None
        if self._cfg.ca_pem.strip():
            return ssl.create_default_context(cadata=self._cfg.ca_pem)
        return ssl.create_default_context(cafile=self._cfg.ca_file or None)  # 校验证书与主机名

    def frames(self, events: Sequence[SiemEvent]) -> list[bytes]:
        return [
            syslog_frame(cef(e, version=__version__), severity=e.severity, hostname=self._hostname,
                         app_name=self._cfg.app_name, now=self._clock())
            for e in events
        ]  # fmt: skip

    async def send(self, events: Sequence[SiemEvent]) -> list[int]:
        if not events:
            return []
        frames = self.frames(events)
        if self._cfg.protocol == "udp":
            await self._udp(frames)
        else:
            await self._stream(frames)
        return [e.alert_id for e in events]

    async def _stream(self, frames: list[bytes]) -> None:
        tls = self.ssl_context()
        kwargs: dict[str, Any] = (
            {"ssl": tls, "server_hostname": self._cfg.host} if tls is not None else {}
        )
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(self._cfg.host, self._cfg.port, **kwargs), TIMEOUT
        )
        try:
            for frame in frames:
                writer.write(octet_framed(frame))
            await asyncio.wait_for(writer.drain(), TIMEOUT)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)

    async def _udp(self, frames: list[bytes]) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=(self._cfg.host, self._cfg.port)
        )
        try:
            for frame in frames:
                transport.sendto(frame[:MAX_UDP])
        finally:
            transport.close()


class WebhookSender:
    name = "webhook"

    def __init__(
        self,
        http: RateLimitedHttpClient,
        cfg: WebhookChannel,
        *,
        key: bytes | None,
        token: str | None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._http, self._cfg, self._key, self._token, self._clock = http, cfg, key, token, clock

    def request(self, event: SiemEvent) -> tuple[bytes, dict[str, str]]:
        doc = mask_deep(hec_payload(event) if self._cfg.format == "splunk_hec" else event.to_json())
        body = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": f"opti-alert-{event.alert_id}",
        }
        if self._key is not None:
            ts = int(self._clock())
            headers[TIMESTAMP_HEADER], headers[SIGNATURE_HEADER] = (
                str(ts),
                sign(self._key, ts, body),
            )
        if self._token:
            headers[self._cfg.token_header] = f"{self._cfg.token_prefix}{self._token}"
        return body, headers

    async def send(self, events: Sequence[SiemEvent]) -> list[int]:
        done: list[int] = []
        for event in events:
            body, headers = self.request(event)
            try:
                resp = await self._http.post_bytes(
                    self._cfg.url, body, headers=headers, timeout=self._cfg.timeout_seconds
                )
            except HttpError as e:  # 不记录异常文本：URL 中可能带令牌
                log.warning(
                    "SIEM Webhook 推送失败（告警 %s，%s），本轮停止",
                    event.alert_id,
                    e.status or "网络错误",
                )
                break
            if not 200 <= resp.status_code < 300:
                log.warning(
                    "SIEM Webhook 返回 %s（告警 %s），本轮停止", resp.status_code, event.alert_id
                )
                break
            done.append(event.alert_id)
        return done


def siem_problems(
    cfg: SiemSettings, *, signing_key: str | None, webhook_token: str | None
) -> list[str]:
    if not cfg.webhook.enabled:
        return []
    if cfg.webhook.format == "json" and not (signing_key and len(signing_key) >= MIN_KEY_LENGTH):
        return [f"SIEM Webhook（json）需要签名密钥（至少 {MIN_KEY_LENGTH} 个字符）"]
    if cfg.webhook.format == "splunk_hec" and not webhook_token:
        return ["SIEM Webhook（splunk_hec）需要令牌"]
    return []


def build_senders(
    cfg: SiemSettings,
    http: RateLimitedHttpClient,
    *,
    signing_key: str | None,
    webhook_token: str | None,
) -> tuple[list[Sender], list[str]]:
    senders: list[Sender] = []
    if cfg.syslog.enabled:
        senders.append(SyslogSender(cfg.syslog))
    problems = siem_problems(cfg, signing_key=signing_key, webhook_token=webhook_token)
    if cfg.webhook.enabled and not problems:
        key = signing_key.encode() if signing_key and len(signing_key) >= MIN_KEY_LENGTH else None
        senders.append(WebhookSender(http, cfg.webhook, key=key, token=webhook_token))
    for problem in problems:
        log.warning("%s，Webhook 推送不可用", problem)
    return senders, problems


class SenderCache:
    def __init__(self, http: RateLimitedHttpClient) -> None:
        self._http = http
        self._digest: str | None = None
        self._senders: list[Sender] = []

    def get(self, snapshot: Any) -> list[Sender]:
        digest = snapshot.digest("sharing")
        if digest != self._digest:
            secrets = snapshot.secrets("sharing")
            self._senders, _ = build_senders(
                snapshot.sharing.siem,
                self._http,
                signing_key=secrets.get("siem_signing_key"),
                webhook_token=secrets.get("siem_webhook_token"),
            )
            self._digest = digest
        return self._senders
