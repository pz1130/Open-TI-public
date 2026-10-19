import base64
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from opti.alerting.views import AlertView
from opti.sdk.testing import make_http
from opti.tickets.config import ServiceNowConfig
from opti.tickets.remote import TicketRemoteError
from opti.tickets.servicenow import ServiceNowTicketClient

T = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
VIEW = AlertView(
    alert_id=7, project_id="p", severity="critical", category="phishing_site", domain="acme-loans.com",
    score=95, reasons=("brand_label",), first_seen=T, created_at=T, link="https://ti.example/alerts/7",
)  # fmt: skip
BASIC = ServiceNowConfig(
    base_url="https://acme.service-now.com", table="sn_si_incident", username="opti",
    urgency_impact_map={"critical": {"urgency": 1, "impact": 1}},
    extra_fields={"assignment_group": "Security Operations"},
)  # fmt: skip
OAUTH = ServiceNowConfig(base_url="https://acme.service-now.com", auth="oauth", client_id="cid")
SECRET = "sn-" + "secret-value"
EXPOSURE = {"exposure": {"source": "hibp", "accounts": ["a@acme.org"], "data_classes": []}}
TABLE = "/api/now/table/sn_si_incident"


class Now:
    """假 ServiceNow。tokens：依次发放的令牌；reject_bearer：这些令牌在业务请求中返回 401。"""

    def __init__(
        self,
        *,
        found: list[dict[str, str]] | None = None,
        create: httpx.Response | None = None,
        reject_bearer: tuple[str, ...] = (),
    ) -> None:
        self.calls: list[httpx.Request] = []
        self.found = found or []
        self.create = create or httpx.Response(
            201, json={"result": {"number": "SIR0010001", "sys_id": "abc"}}
        )
        self.tokens = iter(["t1", "t2", "t3"])
        self.reject_bearer = reject_bearer

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == "/oauth_token.do":
            return httpx.Response(200, json={"access_token": next(self.tokens), "expires_in": 1800})
        auth = request.headers.get("Authorization", "")
        if auth.removeprefix("Bearer ") in self.reject_bearer:
            return httpx.Response(401)
        if request.method == "GET":
            return httpx.Response(200, json={"result": self.found})
        if request.method == "POST":
            return self.create
        if request.method == "PATCH":
            return httpx.Response(200, json={"result": {"number": "SIR0010001"}})
        return httpx.Response(405)

    def business(self) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.path != "/oauth_token.do"]


def _client(now: Now, cfg: ServiceNowConfig = BASIC, *, include_accounts: bool = False,
            clock: Any = None) -> ServiceNowTicketClient:  # fmt: skip
    return ServiceNowTicketClient(
        cfg, secret=SECRET, include_accounts=include_accounts,
        http_factory=lambda: make_http(now), **({"clock": clock} if clock else {}),
    )  # fmt: skip


async def test_creates_record_after_dedup_miss() -> None:
    now = Now()
    result = await _client(now).push(VIEW)
    assert result.ref == "SIR0010001" and result.channel == "servicenow"
    search, create = now.calls
    assert (
        search.url.path == TABLE
        and search.url.params["sysparm_query"] == "correlation_id=opti-alert-7"
    )
    basic = base64.b64encode(f"opti:{SECRET}".encode()).decode()
    assert create.headers["Authorization"] == f"Basic {basic}"
    body = json.loads(create.content)
    assert body["short_description"] == "[Open-TI][严重] 钓鱼网站：acme-loans[.]com"
    assert body["correlation_id"] == "opti-alert-7" and body["correlation_display"] == "Open-TI"
    assert body["urgency"] == "1" and body["impact"] == "1"
    assert body["assignment_group"] == "Security Operations"
    assert "告警编号：7" in body["description"]


async def test_dedup_hit_does_not_create() -> None:
    now = Now(found=[{"number": "SIR0000009", "sys_id": "s9", "correlation_id": "opti-alert-7"}])
    assert (await _client(now).push(VIEW)).ref == "SIR0000009"
    assert [c.method for c in now.calls] == ["GET"]
    assert now.calls[0].url.params["sysparm_fields"] == "number,sys_id,correlation_id"


@pytest.mark.parametrize(
    "row",
    [
        {"number": "INC0000001", "sys_id": "x"},
        {"number": "INC0000001", "sys_id": "x", "correlation_id": ""},
    ],
)
async def test_unrelated_row_is_not_a_dedup_hit(row: dict[str, str]) -> None:
    # 表上没有 correlation_id 时，ServiceNow 可能忽略该条件、返回无关记录
    now = Now(found=[row])
    assert (await _client(now).push(VIEW)).ref == "SIR0010001"
    assert [c.method for c in now.calls] == ["GET", "POST"]


async def test_comment_requires_matching_number() -> None:
    now = Now(found=[{"number": "INC0000001", "sys_id": "x"}])
    with pytest.raises(TicketRemoteError) as info:
        await _client(now).push(VIEW, EXPOSURE, existing_ref="SIR0000009")
    assert info.value.detail == "ticket not found"
    assert [c.method for c in now.calls] == ["GET"]  # 不 PATCH 无关记录


async def test_check_rejects_table_without_correlation_id() -> None:
    with pytest.raises(TicketRemoteError) as info:
        await _client(Now(found=[{"number": "X0000001"}])).check()
    assert info.value.kind == "rejected" and info.value.fields == ("correlation_id",)
    await _client(Now(found=[{"number": "X0000001", "correlation_id": ""}])).check()


async def test_existing_ref_writes_work_notes() -> None:
    now = Now(found=[{"number": "SIR0000009", "sys_id": "s9"}])
    result = await _client(now).push(VIEW, EXPOSURE, existing_ref="SIR0000009")
    assert result.ref == "SIR0000009"
    lookup, patch = now.calls
    assert lookup.url.params["sysparm_query"] == "number=SIR0000009"
    assert patch.method == "PATCH" and patch.url.path == f"{TABLE}/s9"
    notes = json.loads(patch.content)["work_notes"]
    assert notes.startswith("Open-TI 告警 7：新增受影响账户 1 个") and "a@acme.org" not in notes


async def test_existing_ref_not_found() -> None:
    with pytest.raises(TicketRemoteError) as info:
        await _client(Now()).push(VIEW, existing_ref="SIR404")
    assert info.value.kind == "rejected" and info.value.detail == "ticket not found"


async def test_oauth_token_is_cached_until_near_expiry() -> None:
    now = Now()
    t = [0.0]
    client = _client(now, OAUTH, clock=lambda: t[0])
    await client.push(VIEW)
    await client.push(VIEW)
    form = parse_qs(now.calls[0].content.decode())
    assert form == {
        "grant_type": ["client_credentials"],
        "client_id": ["cid"],
        "client_secret": [SECRET],
    }
    assert [c.url.path for c in now.calls].count("/oauth_token.do") == 1
    assert {c.headers["Authorization"] for c in now.business()} == {"Bearer t1"}
    t[0] = 1800 - 59  # 到期前 60 秒内：刷新
    await client.push(VIEW)
    assert now.business()[-1].headers["Authorization"] == "Bearer t2"


async def test_oauth_401_refreshes_once_then_reports_auth() -> None:
    now = Now(reject_bearer=("t1",))
    assert (await _client(now, OAUTH).push(VIEW)).ref == "SIR0010001"
    assert [c.headers["Authorization"] for c in now.business()] == [
        "Bearer t1",
        "Bearer t2",
        "Bearer t2",
    ]
    now = Now(reject_bearer=("t1", "t2"))
    with pytest.raises(TicketRemoteError) as info:
        await _client(now, OAUTH).push(VIEW)
    assert info.value.kind == "auth"


async def test_rejected_detail_is_masked_and_short() -> None:
    message = "Invalid field " + "x" * 400
    now = Now(create=httpx.Response(400, json={"error": {"message": message, "detail": ""}}))
    with pytest.raises(TicketRemoteError) as info:
        await _client(now).push(VIEW)
    assert info.value.kind == "rejected" and info.value.detail is not None
    assert len(info.value.detail) == 200
    assert [c.method for c in now.calls].count("POST") == 1  # 建单不重试


async def test_check_reads_table() -> None:
    now = Now()
    await _client(now).check()
    assert now.calls[0].url.params["sysparm_limit"] == "1"
    with pytest.raises(TicketRemoteError) as info:
        await _client(Now(reject_bearer=("t1", "t2")), OAUTH).check()
    assert info.value.kind == "auth"


def test_repr_hides_secret() -> None:
    assert SECRET not in repr(_client(Now()))


async def test_created_without_number_returns_no_ref() -> None:
    # 集成账号读不到 number 字段（ACL）时仍算推送成功，分析员可人工填写编号
    now = Now(create=httpx.Response(201, json={"result": {}}))
    assert (await _client(now).push(VIEW)).ref is None


async def test_oauth_response_without_token_is_auth_error() -> None:
    class LoginPage(Now):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth_token.do":
                self.calls.append(request)
                return httpx.Response(200, text="<html>login</html>")
            return super().__call__(request)

    with pytest.raises(TicketRemoteError) as info:
        await _client(LoginPage(), OAUTH).push(VIEW)
    assert info.value.kind == "auth"
