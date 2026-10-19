import hmac
import json
from datetime import UTC, datetime
from email.message import EmailMessage

import httpx
import pytest

from opti.alerting.config import AlertingConfig
from opti.alerting.views import AlertView
from opti.sdk.testing import make_http
from opti.tickets.client import (
    EmailTicketClient,
    SignatureError,
    WebhookTicketClient,
    build_ticket_client,
    clean_ref,
    sign,
    verify,
)
from opti.tickets.config import TicketsConfig

KEY = b"k" * 32
TS = 1_790_000_000
T = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
VIEW = AlertView(
    alert_id=7, project_id="p", severity="high", category="phishing_site", domain="sbr-loans.com",
    score=80, reasons=("brand_label",), first_seen=T, created_at=T, link="https://ti.example/alerts/7",
)  # fmt: skip


def test_sign_and_verify() -> None:
    body = b'{"alert_id":7}'
    sig = sign(KEY, TS, body)
    now = datetime.fromtimestamp(TS + 10, UTC)
    assert verify(KEY, str(TS), sig, body, now) == TS
    for ts_header, sig_header, payload in [
        (str(TS), "0" * 64, body),  # 签名错误
        (str(TS), sig, b'{"alert_id":8}'),  # 内容被改
        (str(TS - 301), sign(KEY, TS - 301, body), body),  # 超出 300 秒
        ("abc", sig, body),
        (None, sig, body),
        (str(TS), None, body),
    ]:
        with pytest.raises(SignatureError):
            verify(KEY, ts_header, sig_header, payload, now)


def test_clean_ref() -> None:
    assert clean_ref("INC0012345") == "INC0012345" and clean_ref(" OPS-42 ") == "OPS-42"
    assert clean_ref(12345) == "12345"
    assert (
        clean_ref("<script>") is None and clean_ref("a b") is None and clean_ref("x" * 101) is None
    )
    assert clean_ref(None) is None


async def test_webhook_push_signs_exact_bytes() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content
        ts = int(request.headers["X-Opti-Timestamp"])
        assert hmac.compare_digest(request.headers["X-Opti-Signature"], sign(KEY, ts, body))
        seen["payload"] = json.loads(body)
        seen["idem"] = request.headers["Idempotency-Key"]
        return httpx.Response(201, json={"result": {"number": "INC0012345"}})

    client = WebhookTicketClient(
        make_http(handler), "https://itsm.example/hook", KEY, "result.number", clock=lambda: TS
    )
    result = await client.push(VIEW)
    assert result.ref == "INC0012345" and result.channel == "webhook"
    payload = seen["payload"]
    assert isinstance(payload, dict)
    assert payload["domain"] == "sbr-loans[.]com" and payload["alert_id"] == 7
    assert payload["link"] == "https://ti.example/alerts/7" and seen["idem"] == "opti-alert-7"


async def test_webhook_ignores_unusable_ticket_ids() -> None:
    for response in (
        httpx.Response(200, json={"ticket_id": "<script>"}),
        httpx.Response(202, text="accepted"),
    ):
        client = WebhookTicketClient(
            make_http(lambda _r, resp=response: resp), "https://itsm.example/hook", KEY, "ticket_id"
        )
        assert (await client.push(VIEW)).ref is None


async def test_email_ticket() -> None:
    sent: list[EmailMessage] = []

    async def send(msg: EmailMessage) -> None:
        sent.append(msg)

    result = await EmailTicketClient(send, "ti@example.org", ["desk@example.org"]).push(VIEW)
    assert result.ref is None and result.channel == "email"
    msg = sent[0]
    assert msg["Subject"].startswith("[OPTI-ALERT-7]") and msg["To"] == "desk@example.org"
    assert "sbr-loans[.]com" in msg.get_content()


def test_build_ticket_client() -> None:
    http = make_http()
    alerting = AlertingConfig()
    good = {"webhook_url": "https://itsm.example/hook", "signing_key": "s" * 32}
    short = {"webhook_url": "https://itsm.example/hook", "signing_key": "short"}
    assert build_ticket_client(TicketsConfig(), alerting, http, **good) is None  # 未启用
    assert isinstance(
        build_ticket_client(TicketsConfig(enabled=True), alerting, http, **good),
        WebhookTicketClient,
    )
    assert build_ticket_client(TicketsConfig(enabled=True), alerting, http, **short) is None
    assert build_ticket_client(TicketsConfig(enabled=True), alerting, http) is None
    assert (
        build_ticket_client(TicketsConfig(enabled=True, mode="email"), alerting, http, **good)
        is None
    )  # 没有收件人
    email_cfg = TicketsConfig(enabled=True, mode="email", email_to=("desk@example.org",))
    email_alerting = AlertingConfig.model_validate(
        {"smtp": {"host": "relay", "sender": "ti@example.org"}}
    )
    assert isinstance(
        build_ticket_client(email_cfg, email_alerting, http, **good), EmailTicketClient
    )


@pytest.mark.parametrize(
    "ts,sig", [("9" * 4000, "a" * 64), (str(TS), "非ASCII"), (str(TS), "a" * 1000)]
)
def test_malformed_signature_headers(ts, sig):
    with pytest.raises(SignatureError):
        verify(KEY, ts, sig, b"{}", datetime.fromtimestamp(TS, UTC))


async def test_signed_webhook_never_follows_redirect():
    from opti.sdk.http import HttpError

    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(307, headers={"Location": "https://other.example/steal"})

    async with make_http(handler) as http:
        client = WebhookTicketClient(http, "https://ticket.example/create", KEY, "id")
        with pytest.raises(HttpError):
            await client.push(VIEW)
    assert seen == ["https://ticket.example/create"]


async def test_webhook_extra_and_idempotency_key() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["payload"] = json.loads(request.content)
        seen["idem"] = request.headers["Idempotency-Key"]
        return httpx.Response(200, json={})

    client = WebhookTicketClient(
        make_http(handler), "https://itsm.example/hook", KEY, "ticket_id", clock=lambda: TS
    )
    await client.push(
        VIEW, {"exposure": {"accounts": ["a@sbr.int"]}}, idempotency_key="opti-alert-7-accounts-x"
    )
    payload = seen["payload"]
    assert isinstance(payload, dict) and payload["details"] == {
        "exposure": {"accounts": ["a@sbr.int"]}
    }
    assert payload["idempotency_key"] == seen["idem"] == "opti-alert-7-accounts-x"


async def test_email_ticket_extra() -> None:
    sent: list[EmailMessage] = []

    async def send(msg: EmailMessage) -> None:
        sent.append(msg)

    await EmailTicketClient(send, "ti@example.org", ["it@example.org"]).push(
        VIEW, {"exposure": {"accounts": ["a@sbr.int"]}}
    )
    assert "a@sbr.int" in sent[0].get_content()


JIRA = {"base_url": "https://acme.atlassian.net", "email": "ti@acme.org", "project_key": "SEC"}
SN = {"base_url": "https://acme.service-now.com", "table": "sn_si_incident", "username": "opti"}


def test_build_jira_and_servicenow_clients() -> None:
    from opti.tickets.jira import JiraTicketClient
    from opti.tickets.servicenow import ServiceNowTicketClient

    http, alerting = make_http(), AlertingConfig()
    jira = TicketsConfig.model_validate({"enabled": True, "mode": "jira", "jira": JIRA})
    assert build_ticket_client(jira, alerting, http) is None  # 缺 API Token
    assert isinstance(
        build_ticket_client(jira, alerting, http, secrets={"jira_api_token": "t"}), JiraTicketClient
    )
    basic = TicketsConfig.model_validate({"enabled": True, "mode": "servicenow", "servicenow": SN})
    assert (
        build_ticket_client(basic, alerting, http, secrets={"servicenow_client_secret": "x"})
        is None
    )
    assert isinstance(
        build_ticket_client(basic, alerting, http, secrets={"servicenow_password": "p"}),
        ServiceNowTicketClient,
    )
    oauth = TicketsConfig.model_validate(
        {"enabled": True, "mode": "servicenow",
         "servicenow": {"base_url": SN["base_url"], "auth": "oauth", "client_id": "cid"}}
    )  # fmt: skip
    assert build_ticket_client(oauth, alerting, http, secrets={"servicenow_password": "p"}) is None
    assert isinstance(
        build_ticket_client(oauth, alerting, http, secrets={"servicenow_client_secret": "s"}),
        ServiceNowTicketClient,
    )


def test_ticket_url() -> None:
    from opti.tickets.factory import ticket_url

    jira = TicketsConfig.model_validate({"mode": "jira", "jira": JIRA})
    assert ticket_url(jira, "SEC-12") == "https://acme.atlassian.net/browse/SEC-12"
    assert ticket_url(jira, None) is None
    assert ticket_url(jira, "12345") is None  # 不是 Jira 问题键：不生成指向无关问题的链接
    sn = TicketsConfig.model_validate({"mode": "servicenow", "servicenow": SN})
    assert ticket_url(sn, "SIR0010001") == (
        "https://acme.service-now.com/nav_to.do?uri="
        "sn_si_incident.do%3Fsysparm_query%3Dnumber%3DSIR0010001"
    )
    assert ticket_url(TicketsConfig(), "INC1") is None  # Webhook 没有跳转地址
