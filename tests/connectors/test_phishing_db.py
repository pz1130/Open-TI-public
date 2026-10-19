import httpx

from opti.connectors.phishing_db.connector import DOMAINS_URL, LINKS_URL, PhishingDbConnector
from opti.core.config import ProjectRules
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context


async def test_links_and_domains(sbr_rules: ProjectRules) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if str(request.url) == LINKS_URL:
            return httpx.Response(200, text="https://example.org/x\nhttps://evil.top/sbr/login\n")
        if str(request.url) == DOMAINS_URL:
            return httpx.Response(200, text="sbr-grant.top\ncrossbrace.com\n")
        return httpx.Response(404)

    conn = PhishingDbConnector(
        make_context(sbr_rules, connector_id="phishing_db", handler=handler), {}
    )
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert [(i.payload["feed_url"], i.payload["kind"]) for i in items] == [
        ("https://evil.top/sbr/login", "url"),
        ("http://sbr-grant.top/", "domain"),
    ]
    assert items[1].payload["intel"]["list"] == "domains"
    assert requested == [LINKS_URL, DOMAINS_URL]


async def test_lists_are_configurable(sbr_rules: ProjectRules) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, text="")

    conn = PhishingDbConnector(
        make_context(sbr_rules, connector_id="phishing_db", handler=handler), {"lists": ["domains"]}
    )
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
    assert requested == [DOMAINS_URL]
