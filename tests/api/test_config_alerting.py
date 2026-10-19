import json

import httpx
import pytest
from sqlalchemy import select, update

from opti.alerting.config import AlertingConfig, SmtpServer
from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.secretbox import Keyring, generate_key
from opti.db.models import AuditLog, ConfigRevision, ConfigSecret
from tests.api.conftest import ApiWorld

pytestmark = pytest.mark.db

HOOK = "https://hook.example/webhook/abcd1234"


@pytest.fixture
def keyed(api: ApiWorld) -> ApiWorld:
    keyring = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    api.deps.keyring = keyring
    api.deps.config = ConfigRuntime.static(api.rules, sessions=api.sessions, keyring=keyring)
    return api


async def _admin(make_user, login) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    await make_user("ops", ("platform_admin",))
    return await login("ops")


def _cfg(**over: object) -> dict:
    base = {
        "public_base_url": "https://ti.example",
        "channels": [
            {
                "id": "secops",
                "name": "值班",
                "type": "teams",
                "severities": ["critical", "high"],
                "notices": True,
            }
        ],
    }
    return {**base, **over}


async def test_save_with_secrets_is_write_only_and_audited(
    keyed: ApiWorld, make_user, login
) -> None:
    c = await _admin(make_user, login)
    r = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(),
            "base_version": 0,
            "secrets": {"channel:secops:webhook_url": HOOK},
        },
    )
    assert r.status_code == 200, r.text
    assert HOOK not in r.text
    assert keyed.deps.config.snapshot.alerting_secrets["channel:secops:webhook_url"] == HOOK
    listing = (await c.get("/api/v1/config/alerting/secrets")).json()
    assert listing["encryption_key"] is True
    states = {s["name"]: s for s in listing["secrets"]}
    assert states["channel:secops:webhook_url"] == {
        **states["channel:secops:webhook_url"],
        "set": True,
        "hint": "1234",
        "source": "db",
    }
    async with keyed.sessions() as s:
        audit = [(a, d) for a, d in await s.execute(select(AuditLog.action, AuditLog.detail))]
    assert (
        "config.secret_updated",
        {
            "kind": "alerting",
            "replaced": ["channel:secops:webhook_url"],
            "cleared": [],
            "deleted": [],
        },
    ) in audit
    assert HOOK not in json.dumps([d for _, d in audit], ensure_ascii=False)


async def test_secret_only_change_keeps_version(keyed: ApiWorld, make_user, login) -> None:
    c = await _admin(make_user, login)
    await c.put("/api/v1/config/alerting", json={"data": _cfg(), "base_version": 0})
    r = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(),
            "base_version": 1,
            "secrets": {"channel:secops:webhook_url": HOOK},
        },
    )
    assert r.json()["version"] == 1
    assert keyed.deps.config.snapshot.alerting_secrets["channel:secops:webhook_url"] == HOOK


async def test_secret_validation(keyed: ApiWorld, make_user, login) -> None:
    c = await _admin(make_user, login)
    unknown = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(),
            "base_version": 0,
            "secrets": {"channel:other:webhook_url": HOOK},
        },
    )
    assert unknown.status_code == 422
    assert HOOK not in unknown.text
    plain = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(),
            "base_version": 0,
            "secrets": {"channel:secops:webhook_url": "http://x"},
        },
    )
    assert plain.status_code == 422
    assert "http://x" not in plain.text
    keyed.deps.keyring = None
    nokey = await c.put(
        "/api/v1/config/alerting",
        json={"data": _cfg(), "base_version": 0, "secrets": {"smtp_password": "p"}},
    )
    assert nokey.status_code == 409 and nokey.json()["detail"] == {
        "reason": "encryption_key_missing"
    }
    huge = "https://hook.example/" + ("a" * 5000)
    echoed = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(),
            "base_version": 0,
            "secrets": {"channel:secops:webhook_url": huge},
        },
    )
    assert echoed.status_code == 422
    assert "hook.example" not in echoed.text


async def test_removed_channel_secrets_are_deleted(keyed: ApiWorld, make_user, login) -> None:
    c = await _admin(make_user, login)
    saved = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(),
            "base_version": 0,
            "secrets": {"channel:secops:webhook_url": HOOK},
        },
    )
    assert saved.status_code == 200, saved.text
    removed = await c.put(
        "/api/v1/config/alerting", json={"data": _cfg(channels=[]), "base_version": 1}
    )
    assert removed.status_code == 200, removed.text
    async with keyed.sessions() as s:
        assert list(await s.scalars(select(ConfigSecret.name))) == []


async def _corrupt_alerting_head(api: ApiWorld, version: int) -> None:
    async with api.sessions.begin() as s:
        await s.execute(
            update(ConfigRevision)
            .where(ConfigRevision.kind == "alerting", ConfigRevision.version == version)
            .values(content="public_base_url: [\n")
        )


async def test_corrupt_alerting_head_can_be_repaired(keyed: ApiWorld, make_user, login) -> None:
    class Oidc:
        cfg = type("Cfg", (), {"redirect_uri": None})()

    c = await _admin(make_user, login)
    first = await c.put("/api/v1/config/alerting", json={"data": _cfg(), "base_version": 0})
    assert first.status_code == 200, first.text
    v1 = first.json()["version"]
    second = await c.put(
        "/api/v1/config/alerting",
        json={"data": _cfg(report_timezone="Asia/Shanghai"), "base_version": v1},
    )
    assert second.status_code == 200, second.text
    v2 = second.json()["version"]
    assert keyed.deps.public_base_url == "https://ti.example"
    await _corrupt_alerting_head(keyed, v2)

    current = await c.get("/api/v1/config/alerting")
    assert current.status_code == 200, current.text
    assert current.json()["version"] == v2
    assert current.json()["data"]["public_base_url"] == "https://ti.example"

    keyed.deps.oidc = Oidc()  # type: ignore[assignment]
    blocked = await c.put(
        "/api/v1/config/alerting",
        json={"data": _cfg(public_base_url="https://new.example"), "base_version": v2},
    )
    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["detail"]["reason"] == "oidc_redirect_change"
    assert blocked.json()["detail"]["redirect_uri"].startswith("https://new.example/")

    repaired = await c.put(
        "/api/v1/config/alerting",
        json={"data": _cfg(report_timezone="Asia/Shanghai"), "base_version": v2},
    )
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["version"] == v2 + 1

    await _corrupt_alerting_head(keyed, v2 + 1)
    restored = await c.post(
        f"/api/v1/config/alerting/revisions/{v1}/restore",
        json={"base_version": v2 + 1},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["version"] == v2 + 2


async def test_oidc_redirect_change_needs_confirmation(keyed: ApiWorld, make_user, login) -> None:
    class Oidc:
        cfg = type("Cfg", (), {"redirect_uri": None})()

    keyed.deps.oidc = Oidc()  # type: ignore[assignment]
    c = await _admin(make_user, login)
    r = await c.put(
        "/api/v1/config/alerting",
        json={"data": _cfg(public_base_url="https://new.example"), "base_version": 0},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "oidc_redirect_change"
    assert r.json()["detail"]["redirect_uri"].startswith("https://new.example/")
    r = await c.put(
        "/api/v1/config/alerting",
        json={
            "data": _cfg(public_base_url="https://new.example"),
            "base_version": 0,
            "confirm_oidc_change": True,
        },
    )
    assert r.status_code == 200 and keyed.deps.public_base_url == "https://new.example"


async def test_only_platform_admin_writes(keyed: ApiWorld, make_user, login) -> None:
    await make_user("alice", ("analyst",))
    a = await login("alice")
    assert (await a.get("/api/v1/config/alerting")).status_code == 200
    assert (
        await a.put("/api/v1/config/alerting", json={"data": _cfg(), "base_version": 0})
    ).status_code == 403
    assert (await a.get("/api/v1/config/alerting/secrets")).status_code == 403
    assert (
        await a.post("/api/v1/config/alerting/test", json={"channel": _cfg()["channels"][0]})
    ).status_code == 403


async def test_channel_test_teams_and_rate_limit(keyed: ApiWorld, make_user, login) -> None:
    posted: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(200)

    keyed.deps.alerting_transport = httpx.MockTransport(handler)
    c = await _admin(make_user, login)
    body = {"channel": _cfg()["channels"][0], "secrets": {"channel:secops:webhook_url": HOOK}}
    r = await c.post("/api/v1/config/alerting/test", json=body)
    assert r.json() == {"ok": True, "error": None} and len(posted) == 1
    assert "Open-TI" in json.dumps(posted[0], ensure_ascii=False)
    for _ in range(4):
        await c.post("/api/v1/config/alerting/test", json=body)
    assert (await c.post("/api/v1/config/alerting/test", json=body)).status_code == 429


async def test_channel_test_sanitizes_errors(keyed: ApiWorld, make_user, login) -> None:
    keyed.deps.alerting_transport = httpx.MockTransport(
        lambda r: httpx.Response(403, text="token=abcd1234 rejected")
    )
    c = await _admin(make_user, login)
    r = await c.post(
        "/api/v1/config/alerting/test",
        json={
            "channel": _cfg()["channels"][0],
            "secrets": {"channel:secops:webhook_url": HOOK},
        },
    )
    body = r.json()
    assert body["ok"] is False and "403" in body["error"]
    assert "hook.example" not in body["error"] and "abcd1234" not in body["error"]


async def test_channel_test_email(keyed: ApiWorld, make_user, login) -> None:
    sent: list[tuple[str, str | None, str | None]] = []

    def factory(smtp, username, password):  # type: ignore[no-untyped-def]
        async def send(msg):  # type: ignore[no-untyped-def]
            sent.append((msg["To"], username, password))

        return send

    keyed.deps.smtp_sender = factory
    c = await _admin(make_user, login)
    r = await c.post(
        "/api/v1/config/alerting/test",
        json={
            "channel": {
                "id": "mgmt",
                "name": "管理层",
                "type": "email",
                "recipients": ["ciso@example.org"],
            },
            "smtp": {"host": "relay", "port": 587, "starttls": True, "sender": "ti@example.org"},
            "secrets": {"smtp_username": "u", "smtp_password": "p"},
        },
    )
    assert r.json()["ok"] is True and sent == [("ciso@example.org", "u", "p")]


def _email_sender(sent: list[tuple[str, str | None, str | None]]):  # type: ignore[no-untyped-def]
    def factory(smtp, username, password):  # type: ignore[no-untyped-def]
        async def send(msg):  # type: ignore[no-untyped-def]
            sent.append((smtp.host, username, password))

        return send

    return factory


EMAIL_CHANNEL = {
    "id": "mgmt",
    "name": "管理层",
    "type": "email",
    "recipients": ["ciso@example.org"],
}
STORED_SMTP = {"host": "relay.internal", "port": 587, "starttls": True, "sender": "ti@example.org"}


def _store_smtp(api: ApiWorld) -> None:
    override(
        api.deps.config,
        alerting=AlertingConfig(smtp=SmtpServer(**STORED_SMTP)),
        secrets={"alerting": {"smtp_username": "u", "smtp_password": "stored-pw"}},
    )


@pytest.mark.parametrize(
    "change", [{"host": "smtp.attacker.example"}, {"port": 2525}, {"starttls": False}]
)
async def test_channel_test_email_does_not_send_stored_credentials_to_changed_server(
    keyed: ApiWorld, make_user, login, change: dict
) -> None:
    sent: list[tuple[str, str | None, str | None]] = []
    keyed.deps.smtp_sender = _email_sender(sent)
    _store_smtp(keyed)
    c = await _admin(make_user, login)
    r = await c.post(
        "/api/v1/config/alerting/test",
        json={"channel": EMAIL_CHANNEL, "smtp": {**STORED_SMTP, **change}},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False and "重新输入" in r.json()["error"]
    assert sent == []


async def test_channel_test_email_reuses_stored_credentials_for_same_server(
    keyed: ApiWorld, make_user, login
) -> None:
    sent: list[tuple[str, str | None, str | None]] = []
    keyed.deps.smtp_sender = _email_sender(sent)
    _store_smtp(keyed)
    c = await _admin(make_user, login)
    r = await c.post(
        "/api/v1/config/alerting/test",
        json={"channel": EMAIL_CHANNEL, "smtp": {**STORED_SMTP, "sender": "other@example.org"}},
    )
    assert r.json() == {"ok": True, "error": None}
    assert sent == [("relay.internal", "u", "stored-pw")]


async def test_channel_test_email_uses_reentered_credentials_for_changed_server(
    keyed: ApiWorld, make_user, login
) -> None:
    sent: list[tuple[str, str | None, str | None]] = []
    keyed.deps.smtp_sender = _email_sender(sent)
    _store_smtp(keyed)
    c = await _admin(make_user, login)
    r = await c.post(
        "/api/v1/config/alerting/test",
        json={
            "channel": EMAIL_CHANNEL,
            "smtp": {**STORED_SMTP, "host": "relay2.internal"},
            "secrets": {"smtp_username": "u2", "smtp_password": "new-pw"},
        },
    )
    assert r.json() == {"ok": True, "error": None}
    assert sent == [("relay2.internal", "u2", "new-pw")]
