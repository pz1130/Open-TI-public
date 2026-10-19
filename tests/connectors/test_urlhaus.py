import httpx

from opti.connectors.urlhaus.connector import API_URL, UrlhausConnector
from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

KEY = "u" * 48
BODY = {
    "query_status": "ok",
    "urls": [
        {"id": 1, "url": "http://sbr-grants.top/payload.exe", "url_status": "online",
         "threat": "malware_download", "tags": ["exe"], "date_added": "2026-10-02 07:00:00 UTC"},
        {"id": 2, "url": "http://random.example/bin.sh", "url_status": "online", "threat": "malware_download"},
    ],
}  # fmt: skip


def _connector(rules: ProjectRules, handler) -> UrlhausConnector:  # type: ignore[no-untyped-def]
    secrets = EnvSecretProvider({"OPTI_SECRET_URLHAUS_AUTH_KEY": KEY})
    return UrlhausConnector(
        make_context(rules, connector_id="urlhaus", handler=handler, secrets=secrets), {}
    )


async def test_recent_urls(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == API_URL and request.headers["Auth-Key"] == KEY
        return httpx.Response(200, json=BODY)

    items = [i async for i in _connector(sbr_rules, handler).fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1
    intel = items[0].payload["intel"]
    assert intel["source"] == "urlhaus" and intel["confirmed"] is True and intel["urlhaus_id"] == 1
    assert intel["threat"] == "malware_download" and intel["tags"] == ["exe"]


async def test_bad_status_ends_quietly(sbr_rules: ProjectRules) -> None:
    items = [
        i
        async for i in _connector(
            sbr_rules, lambda _r: httpx.Response(200, json={"query_status": "unknown_auth_key"})
        ).fetch(build_query_plan(sbr_rules))
    ]
    assert items == []
