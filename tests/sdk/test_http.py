import json

import httpx
import pytest

from opti.sdk.http import DEFAULT_USER_AGENT, HttpError, HttpPolicy, TokenBucket
from opti.sdk.testing import FakeTime, make_http


def _sequence(*responses: httpx.Response | Exception):
    calls: list[httpx.Request] = []
    items = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        r = items.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    return handler, calls


async def test_user_agent_is_sent() -> None:
    handler, calls = _sequence(httpx.Response(200, text="ok"))
    async with make_http(handler) as http:
        await http.get("https://a.example/x")
    assert calls[0].headers["User-Agent"] == DEFAULT_USER_AGENT


async def test_retries_with_backoff_then_succeeds() -> None:
    t = FakeTime()
    handler, calls = _sequence(httpx.Response(503), httpx.Response(503), httpx.Response(200))
    http = make_http(handler, policy=HttpPolicy(max_retries=3), time=t)
    resp = await http.get("https://a.example/x")
    assert resp.status_code == 200 and len(calls) == 3
    assert t.sleeps == [1.0, 2.0]


async def test_retry_after_is_honoured() -> None:
    t = FakeTime()
    handler, _ = _sequence(httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200))
    await make_http(handler, policy=HttpPolicy(max_retries=1), time=t).get("https://a.example/")
    assert t.sleeps == [7.0]


async def test_gives_up_after_max_retries() -> None:
    t = FakeTime()
    handler, calls = _sequence(*(httpx.Response(502) for _ in range(3)))
    with pytest.raises(HttpError) as exc:
        await make_http(handler, policy=HttpPolicy(max_retries=2), time=t).get("https://a.example/")
    assert exc.value.status == 502 and len(calls) == 3 and len(t.sleeps) == 2


async def test_client_errors_are_not_retried() -> None:
    handler, calls = _sequence(httpx.Response(404))
    with pytest.raises(HttpError) as exc:
        await make_http(handler, policy=HttpPolicy(max_retries=3)).get("https://a.example/")
    assert exc.value.status == 404 and len(calls) == 1


async def test_transport_errors_are_retried() -> None:
    handler, calls = _sequence(httpx.ConnectError("boom"), httpx.Response(200))
    resp = await make_http(handler, policy=HttpPolicy(max_retries=1)).get("https://a.example/")
    assert resp.status_code == 200 and len(calls) == 2


async def test_transport_error_after_retries_has_no_status() -> None:
    handler, _ = _sequence(httpx.ConnectError("a"), httpx.ConnectError("b"))
    with pytest.raises(HttpError) as exc:
        await make_http(handler, policy=HttpPolicy(max_retries=1)).get("https://a.example/")
    assert exc.value.status is None


async def test_body_size_limit() -> None:
    handler, _ = _sequence(httpx.Response(200, content=b"x" * 11))
    with pytest.raises(HttpError, match="上限"):
        await make_http(handler, policy=HttpPolicy(max_body_bytes=10)).get("https://a.example/")


async def test_token_bucket_spaces_requests() -> None:
    t = FakeTime()
    bucket = TokenBucket(2.0, 1.0, clock=t.clock, sleep=t.sleep)
    for _ in range(3):
        await bucket.acquire()
    assert t.sleeps == [0.5, 0.5]


async def test_per_host_rate() -> None:
    t = FakeTime()
    handler, _ = _sequence(*(httpx.Response(200) for _ in range(3)))
    http = make_http(handler, policy=HttpPolicy(per_host_rate=1.0, per_host_burst=1.0), time=t)
    await http.get("https://a.example/1")
    await http.get("https://b.example/1")
    assert t.sleeps == []
    await http.get("https://a.example/2")
    assert t.sleeps == [1.0]


async def test_cookies_are_not_persisted_by_default() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "sid=1; Path=/"})

    http = make_http(handler)
    await http.get("https://a.example/1")
    await http.get("https://a.example/2")
    assert seen == [None, None]


async def test_cookies_persist_when_enabled() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "sid=1; Path=/"})

    http = make_http(handler, policy=HttpPolicy(persist_cookies=True))
    await http.get("https://a.example/1")
    await http.get("https://a.example/2")
    assert seen == [None, "sid=1"]


async def test_post_json_retries() -> None:
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        bodies.append(request.content)
        return httpx.Response(503 if len(bodies) == 1 else 200)

    resp = await make_http(handler).post_json("https://hook.example/x", {"a": 1})
    assert resp.status_code == 200 and len(bodies) == 2
    assert json.loads(bodies[0]) == {"a": 1}


def _endless(pulled: list[int]) -> httpx.Response:
    async def body():  # type: ignore[no-untyped-def]
        while True:
            pulled.append(1)
            yield b"x" * 1024

    return httpx.Response(200, headers={"content-type": "text/html"}, content=body())


async def test_oversized_body_is_not_buffered() -> None:
    """可疑站点可以返回无限长的响应：超过上限就停止读取，不能先全部读进内存再判断。"""
    pulled: list[int] = []
    http = make_http(lambda _r: _endless(pulled), policy=HttpPolicy(max_body_bytes=10_000))
    with pytest.raises(HttpError, match="响应体超过上限"):
        await http.get("https://a.example/")
    assert len(pulled) <= 12


async def test_truncate_body_keeps_prefix() -> None:
    pulled: list[int] = []
    http = make_http(lambda _r: _endless(pulled))
    resp = await http.get("https://a.example/", max_body_bytes=2500, truncate_body=True)
    assert resp.status_code == 200 and resp.content == b"x" * 2500
    assert resp.headers["content-type"] == "text/html"
    assert len(pulled) <= 4


async def test_compressed_body_is_decoded() -> None:
    import gzip

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-encoding": "gzip"}, content=gzip.compress("你好".encode())
        )

    resp = await make_http(handler).get("https://a.example/")
    assert resp.text == "你好"


async def test_post_json_accepts_timeout() -> None:
    seen: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions.get("timeout"))
        return httpx.Response(200, json={"ok": True})

    resp = await make_http(handler).post_json("https://a.example/hook", {"x": 1}, timeout=55.0)
    assert resp.json() == {"ok": True}
    assert seen and seen[0]["read"] == 55.0  # type: ignore[index]


def test_default_user_agent_is_generic() -> None:
    assert DEFAULT_USER_AGENT.startswith("Open-TI/")
    assert "SBR" not in DEFAULT_USER_AGENT


async def test_post_form() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})

    resp = await make_http(handler).post_form(
        "https://login.example/token", {"grant_type": "client_credentials"}
    )
    assert resp.json()["access_token"] == "t"
    assert seen[0].method == "POST"
    assert seen[0].headers["content-type"] == "application/x-www-form-urlencoded"
    assert seen[0].content == b"grant_type=client_credentials"


async def test_malwarebazaar_query_is_fixed_and_does_not_follow_redirects() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example/get_file"})

    response = await make_http(handler).malwarebazaar_recent("test-key")
    assert response.status_code == 302 and len(seen) == 1
    assert str(seen[0].url) == "https://mb-api.abuse.ch/api/v1/"
    assert seen[0].method == "POST"
    assert seen[0].content == b"query=get_recent&selector=time"
    assert seen[0].headers["Auth-Key"] == "test-key"


async def test_request_json_sends_method_body_and_params() -> None:
    handler, calls = _sequence(httpx.Response(201, json={"key": "SEC-1"}))
    async with make_http(handler) as http:
        resp = await http.request_json(
            "PATCH", "https://api.example/t/1", headers={"Authorization": "Basic x"},
            json={"a": 1}, params={"sysparm_fields": "number"}, max_retries=0,
        )  # fmt: skip
    assert resp.json() == {"key": "SEC-1"}
    assert calls[0].method == "PATCH" and json.loads(calls[0].content) == {"a": 1}
    assert calls[0].url.params["sysparm_fields"] == "number"
    assert calls[0].headers["Authorization"] == "Basic x"


async def test_request_json_keeps_error_body_and_does_not_retry_when_asked() -> None:
    handler, calls = _sequence(httpx.Response(400, json={"errors": {"priority": "bad"}}))
    async with make_http(handler) as http:
        with pytest.raises(HttpError) as info:
            await http.request_json(
                "POST", "https://api.example/t", headers={}, json={}, max_retries=0
            )
    assert info.value.status == 400 and json.loads(info.value.body or b"") == {
        "errors": {"priority": "bad"}
    }
    handler, calls = _sequence(httpx.Response(503), httpx.Response(200))
    async with make_http(handler) as http:
        with pytest.raises(HttpError):
            await http.request_json(
                "POST", "https://api.example/t", headers={}, json={}, max_retries=0
            )
    assert len(calls) == 1  # 非幂等请求：调用方要求不重试


async def test_request_json_error_body_is_capped_and_get_errors_have_no_body() -> None:
    handler, _ = _sequence(httpx.Response(500, content=b"x" * 40_000))
    async with make_http(handler) as http:
        with pytest.raises(HttpError) as info:
            await http.request_json("GET", "https://api.example/t", headers={}, max_retries=0)
    assert info.value.body is not None and len(info.value.body) == 16 * 1024
    handler, _ = _sequence(httpx.Response(404, text="nope"))
    async with make_http(handler) as http:
        with pytest.raises(HttpError) as info:
            await http.get("https://api.example/t")
    assert info.value.body is None


async def test_request_json_does_not_follow_redirects() -> None:
    handler, calls = _sequence(httpx.Response(302, headers={"Location": "https://evil.example/"}))
    async with make_http(handler) as http:
        resp = await http.request_json(
            "GET", "https://api.example/t", headers={"Authorization": "Basic x"}
        )
    assert resp.status_code == 302 and len(calls) == 1
