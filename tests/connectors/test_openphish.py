import httpx

from opti.connectors.openphish.connector import FEED_URL, OpenPhishConnector
from opti.core.config import ProjectRules
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

FEED = "\n".join([
    "https://sbr-loans.com/secure/login.php",
    "https://paypal-verify.example/login",
    "https://storage.googleapis.com/bucket-x/samplebrand/index.html",
    "",
    "https://sbr.int/",
])  # fmt: skip


def _connector(rules: ProjectRules, handler) -> OpenPhishConnector:  # type: ignore[no-untyped-def]
    return OpenPhishConnector(make_context(rules, connector_id="openphish", handler=handler), {})


async def test_feed_items(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == FEED_URL
        return httpx.Response(200, text=FEED)

    items = [i async for i in _connector(sbr_rules, handler).fetch(build_query_plan(sbr_rules))]
    assert [i.payload["feed_url"] for i in items] == [
        "https://sbr-loans.com/secure/login.php",
        "https://storage.googleapis.com/bucket-x/samplebrand/index.html",
    ]
    assert all(i.payload["intel"]["confirmed"] is True for i in items)


async def test_download_failure_ends_quietly(sbr_rules: ProjectRules) -> None:
    items = [
        i
        async for i in _connector(sbr_rules, lambda _r: httpx.Response(503)).fetch(
            build_query_plan(sbr_rules)
        )
    ]
    assert items == []
