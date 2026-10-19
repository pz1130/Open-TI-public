import httpx

from opti.connectors.urlscan.connector import UrlscanConnector
from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context


def _result(
    url: str, uuid: str, sort: list[object], *, malicious: bool = False
) -> dict[str, object]:
    return {
        "task": {"uuid": uuid, "time": "2026-10-02T07:00:00.000Z", "url": url},
        "page": {"url": url, "domain": url.split("/")[2]},
        "result": f"https://urlscan.io/api/v1/result/{uuid}/",
        "sort": sort,
        "verdicts": {"overall": {"malicious": malicious}},
    }


def test_compile_queries(sbr_rules: ProjectRules) -> None:
    conn = UrlscanConnector(make_context(sbr_rules, connector_id="urlscan"), {})
    q = conn.compile_queries(build_query_plan(sbr_rules))
    assert 'page.title:"Sample Brand"' in q
    assert "page.domain:samplebrand*" in q and "page.domain:orbitbank*" in q
    assert not any("*sbr*" in x for x in q)  # 短品牌词不检索


async def test_search_paginates_and_marks_verdicts(sbr_rules: ProjectRules) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        params = request.url.params
        if not params["q"].startswith('(page.title:"Sample Brand")'):
            return httpx.Response(200, json={"results": [], "has_more": False})
        assert params["q"].endswith("AND date:>now-2d") and params["size"] == "100"
        if "search_after" not in params:
            return httpx.Response(200, json={"results": [
                _result("https://sbr-loans.com/login", "u1", [1, "a"], malicious=True),
                _result("https://example.org/news", "u2", [2, "b"]),
            ], "has_more": True})  # fmt: skip
        assert params["search_after"] == "2,b"
        return httpx.Response(200, json={"results": [
            _result("https://sites.google.com/view/sbr-grants", "u3", [3, "c"]),
        ], "has_more": False})  # fmt: skip

    secrets = EnvSecretProvider({"OPTI_SECRET_URLSCAN_API_KEY": "k" * 36})
    conn = UrlscanConnector(
        make_context(sbr_rules, connector_id="urlscan", handler=handler, secrets=secrets), {}
    )
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert [(i.payload["feed_url"], i.payload["intel"]["confirmed"]) for i in items] == [
        ("https://sbr-loans.com/login", True),
        ("https://sites.google.com/view/sbr-grants", False),
    ]
    assert items[0].payload["intel"]["urlscan_uuid"] == "u1"
    assert all(c.headers["API-Key"] == "k" * 36 for c in calls)


async def test_query_failure_skips_to_next(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["q"].startswith('(page.title:"Sample Brand")'):
            return httpx.Response(400, json={"message": "bad query"})
        return httpx.Response(200, json={"results": [
            _result("https://samplebrand-help.top/", "u9", [9]),
        ], "has_more": False})  # fmt: skip

    conn = UrlscanConnector(make_context(sbr_rules, connector_id="urlscan", handler=handler), {})
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert [i.payload["feed_url"] for i in items] == ["https://samplebrand-help.top/"]


def test_authenticated_domain_queries_use_keyword_field(sbr_rules: ProjectRules) -> None:
    secrets = EnvSecretProvider({"OPTI_SECRET_URLSCAN_API_KEY": "k" * 36})
    conn = UrlscanConnector(make_context(sbr_rules, connector_id="urlscan", secrets=secrets), {})
    assert "page.domain.keyword:*samplebrand*" in conn.compile_queries(
        build_query_plan(sbr_rules)
    )


async def test_duplicate_verdict_keeps_confirmed_and_bad_nested_fields(
    sbr_rules: ProjectRules,
) -> None:
    url = "https://evil.top/sbr/login"

    def handler(request: httpx.Request) -> httpx.Response:
        first = _result(url, "unknown", [1], malicious=False)
        confirmed = _result(url, "confirmed", [2], malicious=True)
        search_shape = _result("https://evil.top/sbr-grants", "nested", [3])
        search_shape["verdicts"] = {"urlscan": {"malicious": True}}
        malformed = {"page": [], "task": 7, "verdicts": "bad"}
        return httpx.Response(
            200, json={"results": [first, confirmed, search_shape, malformed], "has_more": False}
        )

    conn = UrlscanConnector(make_context(sbr_rules, connector_id="urlscan", handler=handler), {})
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 2
    assert all(i.payload["intel"]["confirmed"] is True for i in items)
    assert items[0].payload["intel"]["urlscan_uuid"] == "confirmed"


async def test_missing_pagination_cursor_stops(sbr_rules: ProjectRules) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200, json={"results": [_result("https://evil.top/sbr", "u", [])], "has_more": True}
        )

    conn = UrlscanConnector(make_context(sbr_rules, connector_id="urlscan", handler=handler), {})
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1
    assert len(calls) == len(conn.compile_queries(build_query_plan(sbr_rules)))
