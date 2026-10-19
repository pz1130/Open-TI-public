import httpx
import pytest

from opti.connectors.graphmail import GraphError, GraphMailClient
from opti.sdk.testing import make_http

TOKEN_URL = "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
BASE = "https://graph.microsoft.com/v1.0/users/phishing%40example.org"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _client(handler, clock: Clock | None = None) -> GraphMailClient:  # type: ignore[no-untyped-def]
    return GraphMailClient(
        make_http(handler), tenant_id="tenant-1", client_id="cid", client_secret="sec",
        clock=clock or Clock(),
    )  # fmt: skip


async def test_token_cached_and_messages_paged() -> None:
    tokens = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal tokens
        url = str(request.url)
        if url == TOKEN_URL:
            tokens += 1
            assert b"scope=https%3A%2F%2Fgraph.microsoft.com%2F.default" in request.content
            return httpx.Response(200, json={"access_token": f"tok{tokens}", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer tok1"
        if url.startswith(f"{BASE}/mailFolders/Inbox/messages?"):
            params = request.url.params
            assert params["$filter"] == "receivedDateTime ge 2026-10-01T00:00:00Z"
            assert params["$orderby"] == "receivedDateTime asc"
            return httpx.Response(
                200, json={"value": [{"id": "m1"}], "@odata.nextLink": f"{BASE}/next"}
            )
        if url == f"{BASE}/next":
            return httpx.Response(200, json={"value": [{"id": "m2"}]})
        return httpx.Response(404)

    c = _client(handler)
    msgs = await c.list_messages("phishing@example.org", "Inbox", since="2026-10-01T00:00:00Z")
    assert [m["id"] for m in msgs] == ["m1", "m2"]
    assert tokens == 1


async def test_token_refreshed_before_expiry() -> None:
    clock = Clock()
    issued: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_URL:
            issued.append("x")
            return httpx.Response(
                200, json={"access_token": f"tok{len(issued)}", "expires_in": 120}
            )
        return httpx.Response(200, json={"value": []})

    c = _client(handler, clock)
    await c.attachments("phishing@example.org", "m1")
    clock.now += 30
    await c.attachments("phishing@example.org", "m1")
    clock.now += 40  # 距过期不足 60 秒
    await c.attachments("phishing@example.org", "m1")
    assert len(issued) == 2


async def test_item_attachment_is_expanded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_URL:
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        assert request.url.params["$expand"] == "microsoft.graph.itemattachment/item"
        return httpx.Response(200, json={"item": {"subject": "Reset your password"}})

    item = await _client(handler).item_attachment("phishing@example.org", "m1", "a1")
    assert item["item"]["subject"] == "Reset your password"


async def test_errors_do_not_leak_secrets() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    with pytest.raises(GraphError) as exc:
        await _client(handler).attachments("phishing@example.org", "m1")
    assert "sec" not in str(exc.value) and exc.value.status == 401


async def test_next_link_cannot_exfiltrate_token() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if str(request.url) == TOKEN_URL:
            return httpx.Response(200, json={"access_token": "private-token", "expires_in": 3600})
        return httpx.Response(
            200, json={"value": [{"id": "a"}], "@odata.nextLink": "https://evil.top/steal"}
        )

    with pytest.raises(GraphError, match="分页地址"):
        await _client(handler).list_messages("phishing@example.org", "Inbox", since=None)
    assert seen == ["login.microsoftonline.com", "graph.microsoft.com"]


async def test_graph_redirect_not_followed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if str(request.url) == TOKEN_URL:
            return httpx.Response(200, json={"access_token": "private-token", "expires_in": 3600})
        return httpx.Response(302, headers={"Location": "https://evil.top/steal"})

    with pytest.raises(GraphError) as error:
        await _client(handler).attachments("phishing@example.org", "m1")
    assert error.value.status == 302 and "evil.top" not in seen


@pytest.mark.parametrize(
    "body", [{}, {"access_token": []}, {"access_token": "t", "expires_in": "bad"}, []]
)
async def test_malformed_token_is_safe(body: object) -> None:
    with pytest.raises(GraphError):
        await _client(lambda _r: httpx.Response(200, json=body)).attachments(
            "phishing@example.org", "m1"
        )


async def test_attachments_follow_next_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_URL:
            return httpx.Response(200, json={"access_token": "t"})
        if str(request.url) == f"{BASE}/more":
            return httpx.Response(200, json={"value": [{"id": "a2"}]})
        return httpx.Response(
            200, json={"value": [{"id": "a1"}], "@odata.nextLink": f"{BASE}/more"}
        )

    assert [a["id"] for a in await _client(handler).attachments("phishing@example.org", "m1")] == [
        "a1",
        "a2",
    ]
