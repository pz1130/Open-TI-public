import httpx
import pytest
from sqlalchemy import select

from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.secretbox import Keyring, generate_key
from opti.db.models import AuditLog
from opti.tickets.config import TicketsConfig
from tests.api.conftest import ApiWorld

pytestmark = pytest.mark.db


async def test_ticket_config_and_secrets_refresh(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    keyring = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    api.deps.keyring = keyring
    api.deps.config = ConfigRuntime.static(api.rules, sessions=api.sessions, keyring=keyring)
    await make_user("ops", ("platform_admin",))
    client = await login("ops")
    response = await client.put(
        "/api/v1/config/tickets",
        json={
            "data": {"enabled": True, "mode": "webhook"},
            "base_version": 0,
            "secrets": {"webhook_url": "https://tickets.example/hook", "signing_key": "s" * 32},
        },
    )
    assert response.status_code == 200, response.text
    assert "tickets.example" not in response.text
    assert api.deps.config.snapshot.tickets.enabled
    assert api.deps.tickets_key == b"s" * 32
    secret_state = (await client.get("/api/v1/config/tickets/secrets")).json()
    assert {row["name"] for row in secret_state["secrets"] if row["set"]} == {
        "webhook_url",
        "signing_key",
    }


JIRA = {"base_url": "https://acme.atlassian.net", "email": "ti@acme.org", "project_key": "SEC"}


async def test_tickets_connection_test(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    seen: list[str] = []
    status = {"myself": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/rest/api/3/myself":
            return httpx.Response(status["myself"], json={})
        return httpx.Response(200, json={"issueTypes": [{"name": "Task"}]})

    api.deps.alerting_transport = httpx.MockTransport(handler)
    await make_user("ops", ("platform_admin",))
    await make_user("alice", ("analyst",))
    client = await login("ops")
    url = "/api/v1/config/tickets/test"
    assert (await client.post(url)).status_code == 400  # 默认 Webhook 方式不支持测试
    # 未启用也能测试：先测通再打开
    override(api.deps.config, tickets=TicketsConfig.model_validate({"mode": "jira", "jira": JIRA}))
    assert (await client.post(url)).json() == {
        "ok": False, "kind": "incomplete", "detail": "missing secret",
    }  # fmt: skip
    override(api.deps.config, secrets={"tickets": {"jira_api_token": "t"}})
    assert (await client.post(url)).json() == {"ok": True, "kind": None, "detail": None}
    assert seen == ["/rest/api/3/myself", "/rest/api/3/project/SEC"]
    status["myself"] = 401
    body = (await client.post(url)).json()
    assert body == {"ok": False, "kind": "auth", "detail": "ticket system auth: HTTP 401"}
    assert (await (await login("alice")).post(url)).status_code == 403
    async with api.sessions() as s:
        rows = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "config.tickets_tested"))
        ).all()
    assert [r.detail["kind"] for r in rows] == ["incomplete", None, "auth"]
    for _ in range(2):
        await client.post(url)
    assert (await client.post(url)).status_code == 429  # 每人每分钟 5 次
