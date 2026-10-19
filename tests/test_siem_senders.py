import asyncio
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.config import ProjectRules
from opti.core.siem import SiemEvent
from opti.gateway.pki import make_dev_pki
from opti.sdk.testing import make_http
from opti.sharing import SharingConfig, SiemSettings, SyslogChannel, WebhookChannel
from opti.siem import SenderCache, SyslogSender, WebhookSender, build_senders
from opti.tickets.client import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify

T = datetime(2026, 10, 3, 8, tzinfo=UTC)
KEY = "s" * 40


def _event(i: int) -> SiemEvent:
    return SiemEvent(alert_id=i, project_id="demo", severity="high", category="typosquat_domain", score=70,
                     reasons=("brand_label",), entity_type="domain", entity_value=f"sbr-{i}.top",
                     title=f"sbr-{i}.top", created_at=T, link=f"https://ti.example/alerts/{i}")  # fmt: skip


def _unframe(data: bytes) -> list[bytes]:
    out = []
    while data:
        size, _, rest = data.partition(b" ")
        out.append(rest[: int(size)])
        data = rest[int(size) :]
    return out


async def test_syslog_tcp() -> None:
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read())
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        sender = SyslogSender(SyslogChannel(enabled=True, host="127.0.0.1", port=port, protocol="tcp"),
                              hostname="opti-test", clock=lambda: T)  # fmt: skip
        assert await sender.send([_event(1), _event(2)]) == [1, 2]
        for _ in range(100):
            if received:
                break
            await asyncio.sleep(0.01)
    frames = _unframe(received[0])
    assert len(frames) == 2 and frames[0].startswith(
        b"<131>1 2026-10-03T08:00:00.000Z opti-test opti - opti-alert - CEF:0|"
    )
    assert b"dhost=sbr-2.top" in frames[1]


async def test_syslog_udp() -> None:
    got: list[bytes] = []

    class Collect(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            got.append(data)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(Collect, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        sender = SyslogSender(
            SyslogChannel(enabled=True, host="127.0.0.1", port=port, protocol="udp"),
            clock=lambda: T,
        )
        assert await sender.send([_event(3)]) == [3]
        for _ in range(100):
            if got:
                break
            await asyncio.sleep(0.01)
    finally:
        transport.close()
    assert got[0].startswith(b"<131>1 ") and b"externalId=3" in got[0]


def test_tls_context_verifies_server() -> None:
    ctx = SyslogSender(
        SyslogChannel(enabled=True, host="siem.example", protocol="tls")
    ).ssl_context()
    assert ctx is not None and ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert (
        SyslogSender(SyslogChannel(enabled=True, host="siem.example", protocol="tcp")).ssl_context()
        is None
    )


async def test_syslog_tls_checks_ca_and_hostname(tmp_path: Path) -> None:
    pki = tmp_path / "trusted"
    make_dev_pki(pki, server_names=["localhost"], nodes=[])
    other = tmp_path / "untrusted"
    make_dev_pki(other, server_names=["localhost"], nodes=[])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki / "gateway.pem", pki / "gateway.key")
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read())
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    async with server:
        sender = SyslogSender(
            SyslogChannel(
                enabled=True,
                host="localhost",
                port=port,
                protocol="tls",
                ca_file=str(pki / "ca.pem"),
            )
        )
        assert await sender.send([_event(5)]) == [5]
        for _ in range(100):
            if received:
                break
            await asyncio.sleep(0.01)
        untrusted = SyslogSender(
            SyslogChannel(
                enabled=True,
                host="localhost",
                port=port,
                protocol="tls",
                ca_file=str(other / "ca.pem"),
            )
        )
        with pytest.raises(ssl.SSLCertVerificationError):
            await untrusted.send([_event(6)])
        wrong_host = SyslogSender(
            SyslogChannel(
                enabled=True,
                host="127.0.0.1",
                port=port,
                protocol="tls",
                ca_file=str(pki / "ca.pem"),
            )
        )
        with pytest.raises(ssl.SSLCertVerificationError):
            await wrong_host.send([_event(7)])
    assert b"externalId=5" in received[0]


async def test_webhook_json_is_signed() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(202)

    cfg = WebhookChannel(enabled=True, url="https://siem.example/hook")
    sender = WebhookSender(
        make_http(handler), cfg, key=KEY.encode(), token=None, clock=lambda: T.timestamp()
    )
    assert await sender.send([_event(1)]) == [1]
    req = seen[0]
    verify(
        KEY.encode(), req.headers[TIMESTAMP_HEADER], req.headers[SIGNATURE_HEADER], req.content, T
    )
    body = json.loads(req.content)
    assert body["id"] == "opti-alert-1" and req.headers["idempotency-key"] == "opti-alert-1"
    assert "authorization" not in req.headers


async def test_webhook_splunk_hec() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    cfg = WebhookChannel(enabled=True, url="https://splunk.example:8088/services/collector/event",
                         format="splunk_hec", token_prefix="Splunk ")  # fmt: skip
    sender = WebhookSender(make_http(handler), cfg, key=None, token="hec-token")
    assert await sender.send([_event(4)]) == [4]
    assert (
        seen[0].headers["authorization"] == "Splunk hec-token"
        and SIGNATURE_HEADER.lower() not in seen[0].headers
    )
    assert json.loads(seen[0].content)["sourcetype"] == "opti:alert"


async def test_webhook_stops_on_failure() -> None:
    asked: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        alert_id = json.loads(request.content)["alert_id"]
        asked.append(alert_id)
        return httpx.Response(202 if alert_id == 1 else 503)

    sender = WebhookSender(make_http(handler), WebhookChannel(enabled=True, url="https://siem.example/hook"),
                           key=KEY.encode(), token=None)  # fmt: skip
    assert await sender.send([_event(1), _event(2), _event(3)]) == [1]
    assert set(asked) == {1, 2}  # 第 2 条失败（含一次重试）后停止，第 3 条下轮再发


def test_build_senders() -> None:
    http = make_http(lambda _r: httpx.Response(200))
    assert build_senders(SiemSettings(), http, signing_key=None, webhook_token=None) == ([], [])
    syslog = SiemSettings(syslog=SyslogChannel(enabled=True, host="siem.example"))
    senders, problems = build_senders(syslog, http, signing_key=None, webhook_token=None)
    assert [s.name for s in senders] == ["syslog"] and problems == []
    json_hook = SiemSettings(webhook=WebhookChannel(enabled=True, url="https://siem.example/hook"))
    senders, problems = build_senders(json_hook, http, signing_key="short", webhook_token=None)
    assert senders == [] and "签名密钥" in problems[0]
    senders, problems = build_senders(json_hook, http, signing_key=KEY, webhook_token=None)
    assert [s.name for s in senders] == ["webhook"] and problems == []
    hec = SiemSettings(
        webhook=WebhookChannel(enabled=True, url="https://splunk.example/x", format="splunk_hec")
    )
    senders, problems = build_senders(hec, http, signing_key=None, webhook_token=None)
    assert senders == [] and "令牌" in problems[0]


def test_sender_cache_rebuilds_on_sharing_change(sbr_rules: ProjectRules) -> None:
    runtime = ConfigRuntime.static(sbr_rules)
    cache = SenderCache(make_http(lambda _request: httpx.Response(200)))
    assert cache.get(runtime.snapshot) == []
    override(
        runtime,
        sharing=SharingConfig.model_validate(
            {
                "siem": {
                    "webhook": {"enabled": True, "url": "https://s.example", "format": "json"}
                },
            }
        ),
        secrets={"sharing": {"siem_signing_key": KEY}},
    )
    first = cache.get(runtime.snapshot)
    assert len(first) == 1
    override(runtime, secrets={"sharing": {"siem_signing_key": None}})
    assert cache.get(runtime.snapshot) == []
