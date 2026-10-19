import json
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from opti.alerting.runtime import ConfigBoundTickets
from opti.alerting.views import AlertView
from opti.configs.testing import override
from opti.db.models import Alert, AuditLog
from opti.sdk.http import HttpError
from opti.tickets.client import SIGNATURE_HEADER, TIMESTAMP_HEADER, PushResult, sign
from opti.tickets.config import TicketsConfig
from opti.tickets.remote import TicketRemoteError

pytestmark = pytest.mark.db
KEY = "s" * 40


class FakeTickets:
    name = "fake"

    def __init__(self) -> None:
        self.fail = False
        self.error: Exception | None = None
        self.pushed: list[AlertView] = []
        self.extras: list[Any] = []

    async def push(
        self,
        view: AlertView,
        extra: Any = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        if self.error is not None:
            raise self.error
        if self.fail:
            raise HttpError(view.link, 503, "down")
        self.pushed.append(view)
        self.extras.append(extra)
        return PushResult("INC001", self.name)


def _signed(body: dict[str, Any], ts: int) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    headers = {
        "Content-Type": "application/json",
        TIMESTAMP_HEADER: str(ts),
        SIGNATURE_HEADER: sign(KEY.encode(), ts, raw),
    }
    return raw, headers


async def test_push_and_manual_ref(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    url = f"/api/v1/alerts/{a.alert_id}/ticket"
    assert (await c.post(url)).status_code == 503  # 未配置工单系统
    fake = FakeTickets()
    api.app.state.deps.tickets = fake
    r = await c.post(url)
    assert r.status_code == 200, r.text
    assert r.json()["ref"] == "INC001" and r.json()["pushed_at"] is not None
    assert fake.pushed[0].alert_id == a.alert_id
    assert (await c.post(url)).status_code == 409  # 不重复推送
    ticket = (await c.get(f"/api/v1/alerts/{a.alert_id}")).json()["ticket"]
    assert ticket["ref"] == "INC001" and ticket["available"] is True

    b = await seed_alert("sbr-credit.com")
    r = await c.put(f"/api/v1/alerts/{b.alert_id}/ticket", json={"ticket_ref": "OPS-42"})
    assert (
        r.status_code == 200 and r.json()["ref"] == "OPS-42" and r.json()["pushed_at"] is not None
    )
    assert (
        await c.put(f"/api/v1/alerts/{b.alert_id}/ticket", json={"ticket_ref": "bad ref\n"})
    ).status_code == 422

    fake.fail = True
    d = await seed_alert("sbr-pay.com")
    assert (await c.post(f"/api/v1/alerts/{d.alert_id}/ticket")).status_code == 502
    async with api.sessions() as s:
        assert (await s.get(Alert, d.alert_id)).ticket_pushed_at is None  # type: ignore[union-attr]  # 失败不盖章，可重试
        actions = (
            await s.scalars(
                select(AuditLog.action)
                .where(AuditLog.action.like("ticket.%"))
                .order_by(AuditLog.id)
            )
        ).all()
    assert list(actions) == ["ticket.push", "ticket.set_ref"]


@pytest.mark.parametrize(
    "error,detail",
    [
        (TicketRemoteError("u", 401, "auth"), "ticket system auth: HTTP 401"),
        (TicketRemoteError("u", 400, "rejected", fields=("priority",)),
         "ticket system rejected: HTTP 400 (priority)"),
        (TicketRemoteError("u", None, "unavailable"), "ticket system unavailable: network error"),
    ],
)  # fmt: skip
async def test_remote_errors_explain_502(
    api: Any, make_user: Any, login: Any, seed_alert: Any, error: Exception, detail: str
) -> None:
    alert = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    fake = FakeTickets()
    fake.error = error
    api.app.state.deps.tickets = fake
    r = await c.post(f"/api/v1/alerts/{alert.alert_id}/ticket")
    assert r.status_code == 502 and r.json()["detail"] == detail


async def test_unavailable_bound_tickets_return_503(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    alert = await seed_alert()
    await make_user("alice", ("analyst",))
    client = await login("alice")
    api.app.state.deps.tickets = ConfigBoundTickets(
        lambda: api.app.state.deps.config.snapshot, lambda _snap: None
    )
    response = await client.post(f"/api/v1/alerts/{alert.alert_id}/ticket")
    assert response.status_code == 503
    assert response.json()["detail"] == "ticket integration is not configured"
    async with api.sessions() as s:
        row = await s.get(Alert, alert.alert_id)
        assert row is not None and row.ticket_pushed_at is None


async def test_bound_tickets_still_push(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    alert = await seed_alert()
    await make_user("alice", ("analyst",))
    http = await login("alice")
    ticket = FakeTickets()
    api.app.state.deps.tickets = ConfigBoundTickets(
        lambda: api.app.state.deps.config.snapshot, lambda _snap: ticket
    )
    response = await http.post(f"/api/v1/alerts/{alert.alert_id}/ticket")
    assert response.status_code == 200, response.text
    assert response.json()["ref"] == "INC001" and ticket.pushed[0].alert_id == alert.alert_id


async def test_callback_signature_and_replay(api: Any, seed_alert: Any) -> None:
    a = await seed_alert()
    deps = api.app.state.deps
    override(deps.config, tickets=TicketsConfig(enabled=True, status_map={"resolved": "closed"}),
             secrets={"tickets": {"signing_key": KEY}})  # fmt: skip
    ts = int(api.clock().timestamp())
    url = "/api/v1/integrations/tickets"
    # 服务器间回调：没有 Cookie，也没有 X-Requested-With
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as raw:
        body, headers = _signed(
            {"alert_id": a.alert_id, "ticket_ref": "INC9", "status": "resolved"}, ts
        )
        r = await raw.post(url, content=body, headers=headers)
        assert r.status_code == 200, r.text
        assert (await raw.post(url, content=body, headers=headers)).status_code == 409  # 重放
        assert (
            await raw.post(url, content=body, headers={**headers, SIGNATURE_HEADER: "0" * 64})
        ).status_code == 401
        assert (
            await raw.post(url, content=body + b" ", headers=headers)
        ).status_code == 401  # 内容被改
        old, old_headers = _signed({"alert_id": a.alert_id, "status": "new"}, ts - 301)
        assert (await raw.post(url, content=old, headers=old_headers)).status_code == 401
        other, other_headers = _signed({"alert_id": a.alert_id, "ticket_ref": "OTHER-1"}, ts + 1)
        assert (
            await raw.post(url, content=other, headers=other_headers)
        ).status_code == 409  # 已关联别的工单
        missing, missing_headers = _signed({"alert_id": 999999}, ts + 2)
        assert (await raw.post(url, content=missing, headers=missing_headers)).status_code == 404
        assert (await raw.post(url, content=b"x" * 20000, headers=headers)).status_code == 413
        # 其他写接口仍然要求 X-Requested-With
        assert (await raw.post("/api/v1/auth/logout")).status_code == 403
    async with api.sessions() as s:
        alert = await s.get(Alert, a.alert_id)
        assert alert is not None and alert.ticket_ref == "INC9"
        assert (
            alert.status == "closed"
            and alert.ticket_status == "resolved"
            and alert.closed_at is not None
        )
        actor = await s.scalar(select(AuditLog.actor).where(AuditLog.action == "ticket.callback"))
    assert actor == "integration:tickets"


async def test_callback_not_configured(api: Any) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as raw:
        body, headers = _signed({"alert_id": 1}, int(api.clock().timestamp()))
        assert (
            await raw.post("/api/v1/integrations/tickets", content=body, headers=headers)
        ).status_code == 503


async def test_callback_key_tracks_current_snapshot(api: Any) -> None:
    deps = api.app.state.deps
    override(
        deps.config, tickets=TicketsConfig(enabled=True), secrets={"tickets": {"signing_key": KEY}}
    )
    assert deps.tickets_key == KEY.encode()
    override(deps.config, secrets={"tickets": {"signing_key": "n" * 32}})
    assert deps.tickets_key == b"n" * 32
    override(deps.config, secrets={"tickets": {"signing_key": "short"}})
    assert deps.tickets_key is None


async def test_ticket_url_follows_mode(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    alert = await seed_alert()
    await make_user("alice", ("analyst",))
    c = await login("alice")
    r = await c.put(f"/api/v1/alerts/{alert.alert_id}/ticket", json={"ticket_ref": "SEC-12"})
    assert r.json()["url"] is None  # Webhook 方式没有跳转地址
    jira = {"base_url": "https://acme.atlassian.net", "email": "ti@acme.org", "project_key": "SEC"}
    override(
        api.app.state.deps.config,
        tickets=TicketsConfig.model_validate({"mode": "jira", "jira": jira}),
    )
    ticket = (await c.get(f"/api/v1/alerts/{alert.alert_id}")).json()["ticket"]
    assert ticket["url"] == "https://acme.atlassian.net/browse/SEC-12"
