import base64
from email.message import EmailMessage

import httpx

from opti.connectors.report_mailbox.connector import ReportMailboxConnector
from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

TOKEN_URL = "https://login.microsoftonline.com/t1/oauth2/v2.0/token"
BASE = "https://graph.microsoft.com/v1.0/users/phishing%40example.org"
SECRETS = EnvSecretProvider({
    "OPTI_SECRET_REPORT_MAILBOX_TENANT_ID": "t1",
    "OPTI_SECRET_REPORT_MAILBOX_CLIENT_ID": "c1",
    "OPTI_SECRET_REPORT_MAILBOX_CLIENT_SECRET": "s" * 40,
})  # fmt: skip


def _original() -> str:
    m = EmailMessage()
    m["From"] = "it@helpdesk-login.top"
    m["Subject"] = "Password expiry"
    m.set_content(
        "Reset: https://helpdesk-login.top/reset . Docs: https://learn.microsoft.com/x . Site: https://sbr.int/careers"
    )
    return base64.b64encode(m.as_bytes()).decode()


MESSAGES = [
    {"id": "m-eml", "receivedDateTime": "2026-10-02T08:00:00Z", "subject": "FW: suspicious",
     "from": {"emailAddress": {"address": "employee@example.org"}}, "hasAttachments": True,
     "body": {"contentType": "text", "content": "see attached"}},
    {"id": "m-item", "receivedDateTime": "2026-10-02T08:01:00Z", "subject": "Report", "hasAttachments": True,
     "from": {"emailAddress": {"address": "employee2@example.org"}}, "body": {"contentType": "text", "content": ""}},
    {"id": "m-inline", "receivedDateTime": "2026-10-02T08:02:00Z", "subject": "FW: invoice", "hasAttachments": False,
     "from": {"emailAddress": {"address": "employee3@example.org"}},
     "body": {"contentType": "html", "content": '<a href="https://invoice-portal.top/pay">pay</a>'}},
]  # fmt: skip


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == TOKEN_URL:
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    if url.startswith(f"{BASE}/mailFolders/Inbox/messages"):
        return httpx.Response(200, json={"value": MESSAGES})
    if url == f"{BASE}/messages/m-eml/attachments":
        return httpx.Response(200, json={"value": [
            {"@odata.type": "#microsoft.graph.fileAttachment", "id": "a1", "name": "orig.eml",
             "contentType": "message/rfc822", "contentBytes": _original()},
        ]})  # fmt: skip
    if url == f"{BASE}/messages/m-item/attachments":
        return httpx.Response(200, json={"value": [
            {"@odata.type": "#microsoft.graph.itemAttachment", "id": "a2", "name": "Your mailbox is full"},
        ]})  # fmt: skip
    if url.startswith(f"{BASE}/messages/m-item/attachments/a2"):
        return httpx.Response(200, json={"item": {
            "subject": "Your mailbox is full", "from": {"emailAddress": {"address": "admin@mailbox-quota.top"}},
            "body": {"contentType": "html", "content": '<a href="https://mailbox-quota.top/login">x</a>'},
        }})  # fmt: skip
    return httpx.Response(404)


def _connector(rules: ProjectRules, cursors: MemoryCursorStore) -> ReportMailboxConnector:
    ctx = make_context(
        rules, connector_id="report_mailbox", handler=handler, secrets=SECRETS, cursors=cursors
    )
    return ReportMailboxConnector(ctx, {"mailbox": "phishing@example.org"})


async def test_three_report_shapes(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    items = [i async for i in _connector(sbr_rules, cursors).fetch(build_query_plan(sbr_rules))]
    assert [i.source_item_id for i in items] == ["m-eml", "m-item", "m-inline"]
    eml = items[0].payload
    assert eml["signal"] == "reported" and eml["intel"] == {
        "source": "report_mailbox",
        "confirmed": False,
    }
    assert {"type": "url", "value": "https://helpdesk-login.top/reset"} in eml["indicators"]
    assert {"type": "domain", "value": "helpdesk-login.top"} in eml["indicators"]
    assert (
        eml["context"]["subject"] == "Password expiry"
        and eml["context"]["graph_message_id"] == "m-eml"
    )
    assert "employee@example.org" not in str(eml)  # 不保存举报人地址
    assert cursors.get("report_mailbox", "since") == "2026-10-02T08:02:00Z"


async def test_item_attachment_report(sbr_rules: ProjectRules) -> None:
    items = [
        i
        async for i in _connector(sbr_rules, MemoryCursorStore()).fetch(build_query_plan(sbr_rules))
    ]
    inds = items[1].payload["indicators"]
    assert {"type": "url", "value": "https://mailbox-quota.top/login"} in inds
    assert {"type": "domain", "value": "mailbox-quota.top"} in inds


async def test_ignored_and_official_links_are_skipped(sbr_rules: ProjectRules) -> None:
    items = [
        i
        async for i in _connector(sbr_rules, MemoryCursorStore()).fetch(build_query_plan(sbr_rules))
    ]
    values = [ind["value"] for ind in items[0].payload["indicators"]]
    assert not any("microsoft.com" in v for v in values)  # ignore_domains 默认值
    assert not any("example.org" in v for v in values)  # 举报邮件本身的发件域不作为指标
    # 官方域名的链接由处理器跳过（这里保留，处理器测试已覆盖）


async def test_inline_forward(sbr_rules: ProjectRules) -> None:
    items = [
        i
        async for i in _connector(sbr_rules, MemoryCursorStore()).fetch(build_query_plan(sbr_rules))
    ]
    assert items[2].payload["indicators"] == [
        {"type": "url", "value": "https://invoice-portal.top/pay"}
    ]


async def test_graph_failure_keeps_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    cursors.set("report_mailbox", "since", "2026-10-01T00:00:00Z")
    ctx = make_context(sbr_rules, connector_id="report_mailbox", handler=lambda _r: httpx.Response(503),
                       secrets=SECRETS, cursors=cursors)  # fmt: skip
    items = [
        i
        async for i in ReportMailboxConnector(ctx, {"mailbox": "phishing@example.org"}).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert items == [] and cursors.get("report_mailbox", "since") == "2026-10-01T00:00:00Z"


async def test_binary_attachment_is_only_hashed(sbr_rules: ProjectRules) -> None:
    import hashlib

    binary = b"MZ malicious https://do-not-follow.top/file"

    def binary_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == f"{BASE}/messages/m-inline/attachments":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.fileAttachment",
                            "name": "bad.exe",
                            "contentBytes": base64.b64encode(binary).decode(),
                        }
                    ]
                },
            )
        response = handler(request)
        if str(request.url).startswith(f"{BASE}/mailFolders/Inbox/messages"):
            response = httpx.Response(
                200, json={"value": [{**MESSAGES[2], "hasAttachments": True}]}
            )
        return response

    ctx = make_context(
        sbr_rules, connector_id="report_mailbox", handler=binary_handler, secrets=SECRETS
    )
    items = [
        i
        async for i in ReportMailboxConnector(ctx, {"mailbox": "phishing@example.org"}).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert len(items) == 1
    assert (
        items[0].payload["context"]["attachments"][0]["sha256"]
        == hashlib.sha256(binary).hexdigest()
    )
    assert "do-not-follow" not in str(items[0].payload) and "employee3@" not in str(
        items[0].payload
    )


async def test_equal_timestamp_pagination_resumes_next_run(sbr_rules: ProjectRules) -> None:
    requests: list[int] = []

    def page_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_URL:
            return httpx.Response(200, json={"access_token": "tok"})
        page = int(request.url.params.get("page", "1"))
        requests.append(page)
        data: dict = {
            "value": [
                {
                    "id": f"m{page}",
                    "receivedDateTime": "2026-10-02T08:00:00Z",
                    "body": {"content": f"https://invoice{page}.top/pay"},
                }
            ]
        }
        if page < 5:
            data["@odata.nextLink"] = f"{BASE}/mailFolders/Inbox/messages?page={page + 1}"
        return httpx.Response(200, json=data)

    cursors = MemoryCursorStore()
    ctx = make_context(
        sbr_rules,
        connector_id="report_mailbox",
        handler=page_handler,
        secrets=SECRETS,
        cursors=cursors,
    )
    connector = ReportMailboxConnector(ctx, {"mailbox": "phishing@example.org"})
    first = [i async for i in connector.fetch(build_query_plan(sbr_rules))]
    second = [i async for i in connector.fetch(build_query_plan(sbr_rules))]
    assert [i.source_item_id for i in first + second] == ["m1", "m2", "m3", "m4", "m5"]
    assert requests == [1, 2, 3, 4, 5] and cursors.get("report_mailbox", "next_link") == ""


async def test_inline_reporter_authentication_header_is_not_stored(sbr_rules: ProjectRules) -> None:
    def with_reporter_header(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(f"{BASE}/mailFolders/Inbox/messages"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            **MESSAGES[2],
                            "internetMessageHeaders": [
                                {
                                    "name": "Authentication-Results",
                                    "value": "spf=pass smtp.mailfrom=employee3@example.org",
                                }
                            ],
                        }
                    ]
                },
            )
        return handler(request)

    ctx = make_context(
        sbr_rules, connector_id="report_mailbox", handler=with_reporter_header, secrets=SECRETS
    )
    items = [
        i
        async for i in ReportMailboxConnector(ctx, {"mailbox": "phishing@example.org"}).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert items[0].payload["context"]["auth_results"] is None
    assert "employee3@example.org" not in str(items[0].payload)
