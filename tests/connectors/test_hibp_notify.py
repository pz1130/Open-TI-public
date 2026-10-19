import httpx

from opti.connectors.hibp_notify.connector import HibpNotifyConnector
from opti.core.config import ProjectRules
from opti.core.exposure import breach_catalog, parse_notification
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

TOKEN_URL = "https://login.microsoftonline.com/t1/oauth2/v2.0/token"
BASE = "https://graph.microsoft.com/v1.0/users/security%40sbr.int"
API = "https://haveibeenpwned.com/api/v3"
SECRETS = EnvSecretProvider({"OPTI_SECRET_HIBP_NOTIFY_TENANT_ID": "t1", "OPTI_SECRET_HIBP_NOTIFY_CLIENT_ID": "c1",
                             "OPTI_SECRET_HIBP_NOTIFY_CLIENT_SECRET": "s" * 40})  # fmt: skip
CATALOG = [
    {"Name": "NewLeak", "Title": "New Leak 2026", "BreachDate": "2026-08-01", "DataClasses": ["Passwords"], "IsVerified": True},
    {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Passwords"], "IsVerified": True},
    {"Name": "LinkedIn", "Title": "LinkedIn", "BreachDate": "2012-05-05", "DataClasses": ["Passwords"], "IsVerified": True},
    {"Name": "Gab", "Title": "Gab", "BreachDate": "2021-02-26", "DataClasses": ["Passwords"], "IsVerified": True},
]  # fmt: skip
PASS = [
    {
        "name": "Authentication-Results",
        "value": "spf=pass; dkim=pass; dmarc=pass action=none header.from=haveibeenpwned.com",
    }
]
FAIL = [
    {
        "name": "Authentication-Results",
        "value": "spf=fail; dkim=none; dmarc=fail action=none header.from=haveibeenpwned.com",
    }
]


def _msg(mid: str, *, subject: str, body: str, sender: str = "noreply@haveibeenpwned.com",
         headers: list[dict[str, str]] | None = None, received: str = "2026-10-02T03:00:00Z") -> dict[str, object]:  # fmt: skip
    return {
        "id": mid, "subject": subject, "receivedDateTime": received, "hasAttachments": False,
        "from": {"emailAddress": {"address": sender}}, "internetMessageHeaders": headers or PASS,
        "body": {"contentType": "html", "content": body},
    }  # fmt: skip


GOOD = _msg("m1", subject="Breach notification for sbr.int",
            body="<p>3 email addresses on <b>sbr.int</b> were found in the New Leak 2026 data breach.</p>")  # fmt: skip
NEWSLETTER = _msg("m2", subject="This week on Have I Been Pwned",
                  body="sbr.int subscribers: new breaches loaded — Adobe, LinkedIn and New Leak 2026.")  # fmt: skip
SPOOFED = _msg("m3", subject="Breach notification for sbr.int", headers=FAIL,
               body="2 email addresses on sbr.int were found in the Adobe data breach.")  # fmt: skip
OTHER_DOMAIN = _msg("m4", subject="Breach notification for someone-else.org",
                    body="5 email addresses on someone-else.org were found in the Adobe data breach.")  # fmt: skip
OTHER_SENDER = _msg("m5", subject="Breach notification for sbr.int", sender="alerts@phish.example",
                    body="9 email addresses on sbr.int were found in the Adobe data breach.", received="2026-10-02T05:00:00Z")  # fmt: skip


def test_parse_notification() -> None:
    catalog = breach_catalog(CATALOG)
    kw = {"senders": {"noreply@haveibeenpwned.com"}, "domains": ["sbr.int"], "catalog": catalog}
    note = parse_notification(GOOD, **kw)
    assert note is not None and note.domain == "sbr.int" and note.affected == 3
    assert [b.name for b in note.breaches] == ["NewLeak"]


def test_ignores_unrelated_and_ambiguous_mail() -> None:
    catalog = breach_catalog(CATALOG)
    kw = {"senders": {"noreply@haveibeenpwned.com"}, "domains": ["sbr.int"], "catalog": catalog}
    assert parse_notification(NEWSLETTER, **kw) is None  # 同时提到 3 个以上事件：像新闻简报
    assert parse_notification(SPOOFED, **kw) is None  # DMARC 未通过：可能伪造
    forged_lower_header = _msg(
        "m7",
        subject="Breach notification for sbr.int",
        body="2 email addresses on sbr.int were found in the Adobe data breach.",
        headers=FAIL + PASS,
    )
    assert parse_notification(forged_lower_header, **kw) is None
    assert parse_notification(OTHER_DOMAIN, **kw) is None
    assert parse_notification(OTHER_SENDER, **kw) is None
    # 短事件名（少于 4 个字符）不参与匹配，避免把普通单词当成事件
    gab = _msg(
        "m6", subject="Breach notification for sbr.int", body="Your gab about sbr.int was found."
    )
    assert parse_notification(gab, **kw) is None


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == TOKEN_URL:
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    if url.startswith(f"{BASE}/mailFolders/Inbox/messages"):
        return httpx.Response(
            200, json={"value": [GOOD, NEWSLETTER, SPOOFED, OTHER_DOMAIN, OTHER_SENDER]}
        )
    if url == f"{API}/breaches":
        return httpx.Response(200, json=CATALOG)
    return httpx.Response(404)


async def test_connector_yields_domain_level_exposure(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    ctx = make_context(
        sbr_rules, connector_id="hibp_notify", handler=_handler, secrets=SECRETS, cursors=cursors
    )
    conn = HibpNotifyConnector(ctx, {"mailbox": "security@sbr.int"})
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    [item] = items
    ex = item.payload["exposure"]
    assert ex["key"] == "hibp:sbr.int:NewLeak" and ex["accounts"] == [] and ex["affected"] == 3
    assert ex["source"] == "hibp_notify" and ex["data_classes"] == ["Passwords"]
    assert cursors.get("hibp_notify", "since") == "2026-10-02T05:00:00Z"
