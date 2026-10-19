import base64
import gzip

import httpx

from opti.connectors.dmarc.connector import DmarcConnector
from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider, MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

TOKEN_URL = "https://login.microsoftonline.com/t1/oauth2/v2.0/token"
BASE = "https://graph.microsoft.com/v1.0/users/dmarc%40example.org"
SECRETS = EnvSecretProvider({"OPTI_SECRET_DMARC_TENANT_ID": "t1", "OPTI_SECRET_DMARC_CLIENT_ID": "c1",
                             "OPTI_SECRET_DMARC_CLIENT_SECRET": "s" * 40})  # fmt: skip


def _xml(domain: str, rows: list[tuple[str, int, str, str]]) -> bytes:
    recs = "".join(
        f"<record><row><source_ip>{ip}</source_ip><count>{n}</count><policy_evaluated><disposition>none"
        f"</disposition><dkim>{dkim}</dkim><spf>{spf}</spf></policy_evaluated></row>"
        f"<identifiers><header_from>{domain}</header_from></identifiers></record>"
        for ip, n, dkim, spf in rows
    )
    return (
        f"<feedback><report_metadata><org_name>google.com</org_name><report_id>r-{domain}</report_id>"
        f"<date_range><begin>1790000000</begin><end>1790086400</end></date_range></report_metadata>"
        f"<policy_published><domain>{domain}</domain></policy_published>{recs}</feedback>"
    ).encode()


OWN = _xml("sbr.int", [
    ("45.33.32.156", 140, "fail", "fail"),    # 冒用
    ("40.107.1.1", 900, "pass", "fail"),      # DKIM 对齐通过
    ("192.0.2.10", 30, "fail", "fail"),       # 授权网段内（如转发服务）
    ("45.33.32.200", 2, "fail", "fail"),      # 冒用（少量）
])  # fmt: skip
OTHER = _xml("someone-else.org", [("45.33.32.156", 5, "fail", "fail")])


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == TOKEN_URL:
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    if url.startswith(f"{BASE}/mailFolders/Inbox/messages"):
        return httpx.Response(200, json={"value": [
            {"id": "d1", "receivedDateTime": "2026-10-02T03:00:00Z", "hasAttachments": True},
            {"id": "d2", "receivedDateTime": "2026-10-02T04:00:00Z", "hasAttachments": True},
        ]})  # fmt: skip
    if url == f"{BASE}/messages/d1/attachments":
        return httpx.Response(200, json={"value": [{
            "@odata.type": "#microsoft.graph.fileAttachment", "name": "google.com!sbr.int.xml.gz",
            "contentBytes": base64.b64encode(gzip.compress(OWN)).decode(),
        }]})  # fmt: skip
    if url == f"{BASE}/messages/d2/attachments":
        return httpx.Response(200, json={"value": [{
            "@odata.type": "#microsoft.graph.fileAttachment", "name": "other.xml",
            "contentBytes": base64.b64encode(OTHER).decode(),
        }]})  # fmt: skip
    return httpx.Response(404)


async def test_aligned_and_authorized_sources_are_ignored(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    ctx = make_context(
        sbr_rules, connector_id="dmarc", handler=handler, secrets=SECRETS, cursors=cursors
    )
    conn = DmarcConnector(
        ctx, {"mailbox": "dmarc@example.org", "authorized_networks": ["192.0.2.0/24"]}
    )
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert [i.source_item_id for i in items] == ["google.com:r-sbr.int"]  # 别人域名的报告不处理
    p = items[0].payload
    assert p["signal"] == "dmarc_fail" and p["indicators"] == [
        {"type": "ip", "value": "45.33.32.156", "volume": 140},
        {"type": "ip", "value": "45.33.32.200", "volume": 2},
    ]
    assert p["context"]["failing_messages"] == 142 and p["context"]["total_messages"] == 1072
    assert cursors.get("dmarc", "since") == "2026-10-02T04:00:00Z"
