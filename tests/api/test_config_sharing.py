import asyncio
import json

import httpx

from opti.configs.testing import override
from opti.sharing import SharingConfig
from opti.tickets.client import SIGNATURE_HEADER
from tests.api.conftest import ApiWorld


async def _admin(make_user, login):  # type: ignore[no-untyped-def]
    await make_user("ops", ("platform_admin",))
    return await login("ops")


async def test_sharing_test_webhook_is_signed(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    api.deps.alerting_transport = httpx.MockTransport(handler)
    client = await _admin(make_user, login)
    response = await client.post(
        "/api/v1/config/sharing/test",
        json={
            "target": "webhook",
            "sharing": {
                "siem": {
                    "webhook": {"enabled": True, "url": "https://siem.example/in", "format": "json"}
                }
            },
            "secrets": {"siem_signing_key": "k" * 32},
        },
    )
    assert response.json() == {"ok": True, "error": None}
    payload = json.loads(seen[0].content)
    assert "Open-TI" in json.dumps(payload, ensure_ascii=False)
    assert seen[0].headers.get(SIGNATURE_HEADER)


async def test_sharing_test_does_not_disclose_token(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    api.deps.alerting_transport = httpx.MockTransport(
        lambda _request: httpx.Response(401, text="bad token tok-secret")
    )
    client = await _admin(make_user, login)
    response = await client.post(
        "/api/v1/config/sharing/test",
        json={
            "target": "webhook",
            "sharing": {
                "siem": {
                    "webhook": {
                        "enabled": True,
                        "url": "https://siem.example/in?token=tok-secret",
                        "format": "splunk_hec",
                    }
                }
            },
            "secrets": {"siem_webhook_token": "tok-secret"},
        },
    )
    result = response.json()
    assert result["ok"] is False and "401" in result["error"]
    assert "tok-secret" not in result["error"] and "siem.example" not in result["error"]


async def test_sharing_test_respects_draft_secret_clear(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200)

    override(api.deps.config, secrets={"sharing": {"siem_signing_key": "k" * 32}})
    api.deps.alerting_transport = httpx.MockTransport(handler)
    client = await _admin(make_user, login)
    response = await client.post(
        "/api/v1/config/sharing/test",
        json={
            "target": "webhook",
            "sharing": {"siem": {"webhook": {"enabled": True, "url": "https://siem.example/in"}}},
            "secrets": {"siem_signing_key": None},
        },
    )
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "签名密钥" in response.json()["error"]
    assert sent == []


async def test_sharing_test_syslog_tcp(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read(65536))
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    assert server.sockets is not None
    port = server.sockets[0].getsockname()[1]
    try:
        client = await _admin(make_user, login)
        response = await client.post(
            "/api/v1/config/sharing/test",
            json={
                "target": "syslog",
                "sharing": {
                    "siem": {
                        "syslog": {
                            "enabled": True,
                            "host": "127.0.0.1",
                            "port": port,
                            "protocol": "tcp",
                        }
                    }
                },
                "secrets": {},
            },
        )
    finally:
        server.close()
        await server.wait_closed()
    assert response.json() == {"ok": True, "error": None}
    assert b"Open-TI" in b"".join(received)


STORED_URL = "https://siem.example/in"


def _store_webhook(api: ApiWorld) -> None:
    override(
        api.deps.config,
        sharing=SharingConfig.model_validate(
            {"siem": {"webhook": {"enabled": True, "url": STORED_URL, "format": "splunk_hec"}}}
        ),
        secrets={"sharing": {"siem_webhook_token": "tok-stored", "siem_signing_key": "k" * 32}},
    )


async def test_sharing_test_does_not_send_stored_token_to_changed_url(
    api: ApiWorld, make_user, login
) -> None:  # type: ignore[no-untyped-def]
    sent: list[httpx.Request] = []
    api.deps.alerting_transport = httpx.MockTransport(
        lambda request: sent.append(request) or httpx.Response(200)  # type: ignore[func-returns-value]
    )
    _store_webhook(api)
    client = await _admin(make_user, login)
    response = await client.post(
        "/api/v1/config/sharing/test",
        json={
            "target": "webhook",
            "sharing": {
                "siem": {
                    "webhook": {
                        "enabled": True,
                        "url": "https://collector.attacker.example/in",
                        "format": "splunk_hec",
                    }
                }
            },
            "secrets": {},
        },
    )
    assert response.json()["ok"] is False and "重新输入" in response.json()["error"]
    assert sent == []


async def test_sharing_test_reuses_stored_token_for_same_url(
    api: ApiWorld, make_user, login
) -> None:  # type: ignore[no-untyped-def]
    sent: list[httpx.Request] = []
    api.deps.alerting_transport = httpx.MockTransport(
        lambda request: sent.append(request) or httpx.Response(200)  # type: ignore[func-returns-value]
    )
    _store_webhook(api)
    client = await _admin(make_user, login)
    response = await client.post(
        "/api/v1/config/sharing/test",
        json={
            "target": "webhook",
            "sharing": {
                "siem": {"webhook": {"enabled": True, "url": STORED_URL, "format": "splunk_hec"}}
            },
            "secrets": {},
        },
    )
    assert response.json() == {"ok": True, "error": None}
    assert "tok-stored" in sent[0].headers["Authorization"]
