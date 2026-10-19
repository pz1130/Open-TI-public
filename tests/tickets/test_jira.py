import base64
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from opti.alerting.views import AlertView
from opti.sdk.http import HttpError
from opti.sdk.testing import make_http
from opti.tickets.config import JiraConfig
from opti.tickets.jira import JiraTicketClient
from opti.tickets.remote import TicketRemoteError

T = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
VIEW = AlertView(
    alert_id=7, project_id="p", severity="high", category="phishing_site", domain="acme-loans.com",
    score=80, reasons=("brand_label",), first_seen=T, created_at=T, link="https://ti.example/alerts/7",
)  # fmt: skip
CFG = JiraConfig(
    base_url="https://acme.atlassian.net", email="ti@acme.org", project_key="SEC",
    priority_map={"high": "High"}, extra_fields={"labels": ["drp"], "customfield_10050": {"value": "Brand"}},
)  # fmt: skip
TOKEN = "jira-" + "token-value"
EXPOSURE = {"exposure": {"source": "hibp", "accounts": ["a@acme.org"], "data_classes": []}}


class Jira:
    """按路径应答的假 Jira。"""

    def __init__(self, *, found: str | None = None, create: httpx.Response | None = None) -> None:
        self.calls: list[httpx.Request] = []
        self.found = found
        self.create = create or httpx.Response(201, json={"id": "1", "key": "SEC-12"})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if path == "/rest/api/3/search/jql":
            issues = [{"key": self.found}] if self.found else []
            return httpx.Response(200, json={"issues": issues})
        if path == "/rest/api/3/issue":
            return self.create
        if path.endswith("/comment"):
            return httpx.Response(201, json={"id": "100"})
        if path == "/rest/api/3/myself":
            return httpx.Response(200, json={"accountId": "x"})
        if path == "/rest/api/3/project/SEC":
            return httpx.Response(200, json={"key": "SEC", "issueTypes": [{"name": "Task"}]})
        return httpx.Response(404)

    def body(self, i: int) -> Any:
        return json.loads(self.calls[i].content)


def _client(
    jira: Jira, *, include_accounts: bool = False, cfg: JiraConfig = CFG
) -> JiraTicketClient:
    return JiraTicketClient(
        cfg, TOKEN, include_accounts=include_accounts, http_factory=lambda: make_http(jira)
    )


async def test_creates_issue_after_dedup_miss() -> None:
    jira = Jira()
    result = await _client(jira).push(VIEW)
    assert result.ref == "SEC-12" and result.channel == "jira"
    _search, create = jira.calls
    auth = base64.b64encode(f"ti@acme.org:{TOKEN}".encode()).decode()
    assert create.headers["Authorization"] == f"Basic {auth}"
    assert jira.body(0)["jql"] == 'project = "SEC" AND labels = "opti-alert-7"'
    fields = jira.body(1)["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["issuetype"] == {"name": "Task"}
    assert fields["summary"] == "[Open-TI][高] 钓鱼网站：acme-loans[.]com"
    assert fields["priority"] == {"name": "High"}
    assert fields["labels"] == ["drp", "opti-alert-7"]
    assert fields["customfield_10050"] == {"value": "Brand"}
    assert fields["description"]["type"] == "doc"


async def test_unmapped_severity_sets_no_priority() -> None:
    jira = Jira()
    await _client(jira).push(AlertView(**{**VIEW.__dict__, "severity": "low"}))
    assert "priority" not in jira.body(1)["fields"]


async def test_dedup_hit_does_not_create() -> None:
    jira = Jira(found="SEC-9")
    result = await _client(jira).push(VIEW, idempotency_key="opti-alert-7-accounts-abc")
    assert result.ref == "SEC-9" and len(jira.calls) == 1
    assert jira.body(0)["jql"].endswith('labels = "opti-alert-7-accounts-abc"')


async def test_existing_ref_adds_comment() -> None:
    jira = Jira()
    result = await _client(jira).push(VIEW, EXPOSURE, existing_ref="SEC-9")
    assert result.ref == "SEC-9" and len(jira.calls) == 1
    assert jira.calls[0].url.path == "/rest/api/3/issue/SEC-9/comment"
    assert "a@acme.org" not in json.dumps(jira.body(0))  # include_accounts 关闭
    jira = Jira()
    await _client(jira, include_accounts=True).push(VIEW, EXPOSURE, existing_ref="SEC-9")
    assert "a@acme.org" in json.dumps(jira.body(0))


@pytest.mark.parametrize("ref", ["12345", "INC0012345", "../../rest/api/3/myself", "sec-1"])
async def test_comment_requires_a_jira_issue_key(ref: str) -> None:
    # 切换方式前留下的编号：数字会被 Jira 当成 issue id，评论（可能含员工邮箱）会落到无关问题上
    jira = Jira()
    with pytest.raises(TicketRemoteError) as info:
        await _client(jira).push(VIEW, EXPOSURE, existing_ref=ref)
    assert info.value.kind == "rejected" and jira.calls == []
    assert info.value.public_message() == (
        "ticket system rejected: linked ticket is not a Jira issue key"
    )


@pytest.mark.parametrize(
    "response,kind,fields",
    [
        (httpx.Response(401), "auth", ()),
        (httpx.Response(403), "auth", ()),
        (httpx.Response(400, json={"errorMessages": [], "errors": {"priority": "x", "customfield_1": "y"}}),
         "rejected", ("customfield_1", "priority")),
        (httpx.Response(503), "unavailable", ()),
        (httpx.Response(302, headers={"Location": "https://login.example/"}), "unavailable", ()),
    ],
)  # fmt: skip
async def test_create_errors_are_classified(
    response: httpx.Response, kind: str, fields: tuple[str, ...]
) -> None:
    jira = Jira(create=response)
    with pytest.raises(TicketRemoteError) as info:
        await _client(jira).push(VIEW)
    assert info.value.kind == kind and info.value.fields == fields
    assert isinstance(info.value, HttpError)
    assert info.value.public_message().startswith(f"ticket system {kind}: HTTP ")
    assert len([c for c in jira.calls if c.url.path == "/rest/api/3/issue"]) == 1  # 建单不重试


async def test_public_message_lists_field_names_only() -> None:
    jira = Jira(create=httpx.Response(400, json={"errors": {"priority": "secret-value"}}))
    with pytest.raises(TicketRemoteError) as info:
        await _client(jira).push(VIEW)
    assert info.value.public_message() == "ticket system rejected: HTTP 400 (priority)"


async def test_check() -> None:
    await _client(Jira()).check()
    other = JiraConfig.model_validate({**CFG.model_dump(), "issue_type": "Bug"})
    with pytest.raises(TicketRemoteError) as info:
        await _client(Jira(), cfg=other).check()
    assert info.value.kind == "rejected" and info.value.fields == ("issuetype",)


def test_repr_hides_token() -> None:
    assert TOKEN not in repr(_client(Jira()))


async def test_comment_on_missing_issue_is_rejected() -> None:
    # 键形式正确但问题已删除或不在可见范围
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errorMessages": ["Issue does not exist"], "errors": {}})

    client = JiraTicketClient(
        CFG, TOKEN, include_accounts=False, http_factory=lambda: make_http(handler)
    )
    with pytest.raises(TicketRemoteError) as info:
        await client.push(VIEW, EXPOSURE, existing_ref="SEC-999")
    assert info.value.kind == "rejected" and info.value.status == 404
