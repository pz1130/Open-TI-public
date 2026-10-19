import io
import zipfile
from datetime import date

import httpx

from opti.connectors.nrd.connector import HAGEZI_NRD7_URL, WHOISDS_URL, NrdConnector, whoisds_token
from opti.core.config import ProjectRules
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

HAGEZI = "\n".join(
    [
        "# Title: Newly Registered Domains (NRD)",
        "# Number of entries: 5",
        "0-01x.com",
        "brendble.com",  # 含 sbr 子串的无关域名（2026-10-01 真实数据）
        "landbuyingexperts.com",
        "sbr-loans.com",
        "sbrbank.com",
    ]
)


def _zip(lines: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("domain-names.txt", "\n".join(lines))
    return buf.getvalue()


def test_whoisds_token() -> None:
    assert whoisds_token(date(2026, 10, 1)) == "MjAyNi0xMC0wMS56aXA="


def _connector(
    rules: ProjectRules, cursors: MemoryCursorStore, requests: list[str]
) -> NrdConnector:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == HAGEZI_NRD7_URL:
            return httpx.Response(200, text=HAGEZI)
        if url == WHOISDS_URL.format(token=whoisds_token(date(2026, 10, 1))):
            return httpx.Response(200, content=_zip(["orbitbamk.com", "crossbracerepair.com"]))
        return httpx.Response(404)

    return NrdConnector(
        make_context(rules, connector_id="nrd", handler=handler, cursors=cursors),
        {"sources": ["hagezi_nrd7", "whoisds"], "whoisds_days_back": 2},
        today=lambda: date(2026, 10, 2),
    )


async def test_scans_both_sources(sbr_rules: ProjectRules) -> None:
    cursors, requests = MemoryCursorStore(), []
    items = [
        i async for i in _connector(sbr_rules, cursors, requests).fetch(build_query_plan(sbr_rules))
    ]
    assert [(i.source_item_id, i.payload["source"]) for i in items] == [
        ("sbr-loans.com", "hagezi_nrd7"),
        ("orbitbamk.com", "whoisds:2026-10-01"),
    ]
    assert cursors.get("nrd", "whoisds:last_date") == "2026-10-01"
    assert len(requests) == 3  # hagezi + 09-30（404）+ 10-01


async def test_whoisds_cursor_prevents_redownload(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    cursors.set("nrd", "whoisds:last_date", "2026-10-01")
    requests: list[str] = []
    [i async for i in _connector(sbr_rules, cursors, requests).fetch(build_query_plan(sbr_rules))]
    assert requests == [HAGEZI_NRD7_URL]
