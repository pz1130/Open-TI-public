import json
from collections.abc import Callable

import httpx
import pytest

from opti.core.adjudication import AdjudicationError, PublicInput
from opti.core.code_adjudication import CodeAssessment, CodeInput, RepoMeta, SecretSample
from opti.llm import (
    FAILOVER_AFTER,
    FailoverAdjudicator,
    ProviderAdjudicator,
    ProviderError,
    ProviderSpec,
    make_client,
    open_adjudicator,
    open_provider,
)

INP = PublicInput(
    organization="Example Development Bank", aliases=("EDB",), official_domains=("edb.example",),
    terms=("EDB",), source="Example News", host="news.example", title="EDB issues bond", summary="",
    contexts=("EDB, the ORBIT lender, issued a bond",),
)  # fmt: skip
ANSWER = '{"is_about_org": "yes", "category": "brand_mention", "confidence": 0.9, "rationale": "r", "summary": "s"}'
KEY = "k" * 36 + "WXYZ"
Handler = Callable[[httpx.Request], httpx.Response]


def _spec(**kw: object) -> ProviderSpec:
    base: dict[str, object] = dict(
        id=1, name="DeepSeek", preset="deepseek", protocol="openai", auth="bearer",
        base_url="https://api.deepseek.com/v1", model="deepseek-chat", api_key=KEY,
    )  # fmt: skip
    base.update(kw)
    return ProviderSpec(**base)  # type: ignore[arg-type]


def _chat(content: str = ANSWER) -> httpx.Response:
    return httpx.Response(
        200, json={"choices": [{"message": {"role": "assistant", "content": content}}]}
    )


def _adj(
    spec: ProviderSpec, handler: Handler, seen: list[httpx.Request] | None = None
) -> ProviderAdjudicator:
    def wrapped(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return handler(request)

    return ProviderAdjudicator(spec, make_client(spec, httpx.MockTransport(wrapped)))


async def test_openai_bearer_request() -> None:
    seen: list[httpx.Request] = []
    ans = await _adj(_spec(), lambda _r: _chat(), seen).answer(INP)
    assert (ans.assessment.verdict, ans.backend, ans.model, ans.provider) == (
        "yes", "deepseek", "deepseek-chat", "DeepSeek",
    )  # fmt: skip
    req = seen[0]
    assert str(req.url) == "https://api.deepseek.com/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {KEY}" and "api-key" not in req.headers
    body = json.loads(req.content)
    assert body["model"] == "deepseek-chat" and body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


async def test_azure_api_key_header_and_no_temperature() -> None:
    seen: list[httpx.Request] = []
    spec = _spec(preset="azure_openai", auth="api-key", temperature=None, json_mode=False,
                 base_url="https://res.openai.azure.com/openai/v1", model="my-deploy")  # fmt: skip
    await _adj(spec, lambda _r: _chat(), seen).assess(INP)
    req = seen[0]
    assert req.headers["api-key"] == KEY and "authorization" not in req.headers
    body = json.loads(req.content)
    assert "temperature" not in body and "response_format" not in body


async def test_anthropic_request() -> None:
    seen: list[httpx.Request] = []
    spec = _spec(preset="anthropic", protocol="anthropic", auth="x-api-key", name="Claude",
                 base_url="https://api.anthropic.com/v1", model="claude-sonnet-5-5")  # fmt: skip

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": [{"type": "text", "text": ANSWER}]})

    assert (await _adj(spec, handler, seen).assess(INP)).verdict == "yes"
    req = seen[0]
    assert str(req.url) == "https://api.anthropic.com/v1/messages"
    assert req.headers["x-api-key"] == KEY and req.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(req.content)
    assert body["max_tokens"] == 600 and "untrusted" in body["system"] and body["temperature"] == 0


def _minimax(**kw: object) -> ProviderSpec:
    return _spec(
        **{
            "preset": "minimax",
            "protocol": "anthropic",
            "name": "MiniMax",
            "base_url": "https://api.minimaxi.com/v1",
            "model": "MiniMax-M2.7",
            **kw,
        }
    )


async def test_minimax_messages_request_and_thinking_response() -> None:
    seen: list[httpx.Request] = []
    response = httpx.Response(
        200,
        json={
            "content": [
                {"type": "thinking", "thinking": "private reasoning that is not JSON"},
                {"type": "text", "text": ANSWER},
            ],
            "stop_reason": "end_turn",
        },
    )
    ans = await _adj(_minimax(), lambda _r: response, seen).answer(INP)
    assert (ans.assessment.verdict, ans.backend, ans.model) == ("yes", "minimax", "MiniMax-M2.7")
    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == "https://api.minimax.cn/anthropic/v1/messages"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert req.headers["anthropic-version"] == "2023-06-01" and "x-api-key" not in req.headers
    body = json.loads(req.content)
    assert body["model"] == "MiniMax-M2.7" and body["max_tokens"] == 8192
    assert "untrusted" in body["system"] and body["temperature"] == 0
    assert [m["role"] for m in body["messages"]] == ["user"]
    assert "response_format" not in body and "thinking" not in body


async def test_minimax_truncated_thinking_has_actionable_error() -> None:
    response = httpx.Response(
        200,
        json={
            "stop_reason": "max_tokens",
            "content": [
                {"type": "thinking", "thinking": "private reasoning"},
            ],
        },
    )
    with pytest.raises(ProviderError, match="长度上限") as exc:
        await _adj(_minimax(), lambda _r: response).answer(INP)
    assert "private reasoning" not in str(exc.value)


@pytest.mark.parametrize(
    ("status", "doc", "hint"),
    [
        (401, {"error": {"message": KEY}}, "国内/国际站点不匹配"),
        (404, {"error": {"message": KEY}}, "接口或模型不存在"),
        (429, {"error": {"message": KEY}}, "频率或额度受限"),
        (500, {}, "服务暂时不可用"),
        (200, {"base_resp": {"status_code": 1004, "status_msg": KEY}}, "API Key 无效"),
        (200, {"base_resp": {"status_code": 1008, "status_msg": KEY}}, "账户余额不足"),
        (400, {"base_resp": {"status_code": 2013, "status_msg": KEY}}, "请求参数不兼容"),
        (200, {"base_resp": {"status_code": 2056, "status_msg": KEY}}, "套餐额度受限"),
        (200, {"type": "error", "error": {"message": KEY}}, "服务暂时不可用"),
        (401, {"base_resp": {"status_code": KEY, "status_msg": KEY}}, "API Key 无效"),
    ],
)
async def test_minimax_errors_are_useful_without_echoing_response(
    status: int,
    doc: dict[str, object],
    hint: str,
) -> None:
    with pytest.raises(ProviderError, match=hint) as exc:
        await _adj(_minimax(), lambda _r: httpx.Response(status, json=doc)).answer(INP)
    assert exc.value.status == status and f"HTTP {status}" in str(exc.value)
    assert KEY not in str(exc.value) and KEY[-8:] not in str(exc.value)


async def test_minimax_non_json_error_still_explains_http_status() -> None:
    with pytest.raises(ProviderError, match="HTTP 401") as exc:
        await _adj(_minimax(), lambda _r: httpx.Response(401, text=KEY)).answer(INP)
    assert KEY not in str(exc.value)


async def test_selfhosted_without_key_sends_no_auth() -> None:
    seen: list[httpx.Request] = []
    spec = _spec(preset="selfhosted", api_key=None, base_url="http://vllm:8000/v1", model="qwen")
    await _adj(spec, lambda _r: _chat(), seen).assess(INP)
    assert "authorization" not in seen[0].headers


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401, json={"error": f"invalid key {KEY[-8:]}"}),
        httpx.Response(200, text="<html>gateway</html>"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json=[1, 2]),
        _chat("I cannot help"),
    ],
)
async def test_errors_never_echo_key_or_body(response: httpx.Response) -> None:
    with pytest.raises(AdjudicationError) as e:
        await _adj(_spec(), lambda _r: response).assess(INP)
    assert KEY[-8:] not in str(e.value) and "gateway" not in str(e.value)


async def test_redirect_is_not_followed() -> None:
    seen: list[httpx.Request] = []

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/collect"})

    with pytest.raises(ProviderError, match="重定向") as e:
        await _adj(_spec(), handler, seen).assess(INP)
    assert e.value.status == 302 and [r.url.host for r in seen] == ["api.deepseek.com"]


async def test_network_errors() -> None:
    def timeout(_r: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    def refused(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ProviderError, match="超时"):
        await _adj(_spec(), timeout).assess(INP)
    with pytest.raises(ProviderError, match="网络错误"):
        await _adj(_spec(), refused).assess(INP)


def test_client_ignores_env_proxy_and_hides_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")
    client = make_client(_spec(proxy="socks5://u:" + "pw" + "@proxy.internal:1080"))
    assert client.trust_env is False and client.follow_redirects is False
    assert KEY not in repr(_spec()) and "proxy.internal" not in repr(
        _spec(proxy="http://proxy.internal:1")
    )


async def test_list_models() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET" and request.url.path == "/v1/models"
        return httpx.Response(200, json={"data": [{"id": "b"}, {"id": "a"}, {"id": "a"}, {"x": 1}]})

    assert await _adj(_spec(), handler).list_models() == ["a", "b"]
    for bad in (httpx.Response(404), httpx.Response(200, json={"models": []})):
        with pytest.raises(ProviderError, match="手填"):
            await _adj(_spec(), lambda _r, b=bad: b).list_models()
    with pytest.raises(ProviderError, match="500"):
        await _adj(_spec(), lambda _r: httpx.Response(500)).list_models()


async def test_failover() -> None:
    calls: list[str] = []

    def primary(_r: httpx.Request) -> httpx.Response:
        calls.append("p")
        return httpx.Response(503)

    def backup(_r: httpx.Request) -> httpx.Response:
        calls.append("b")
        return _chat()

    f = FailoverAdjudicator(_adj(_spec(), primary), _adj(_spec(name="Qwen", preset="qwen"), backup))
    for _ in range(FAILOVER_AFTER + 2):
        ans = await f.answer(INP)
        assert ans.provider == "Qwen" and ans.backend == "qwen"
    # 主用连续失败 3 次后，本实例后续调用直接走备用
    assert calls == ["p", "b"] * FAILOVER_AFTER + ["b", "b"]
    assert (f.backend, f.provider) == ("deepseek", "DeepSeek")  # 计划使用的是主用


async def test_failover_both_fail_and_no_backup() -> None:
    down = _adj(_spec(), lambda _r: httpx.Response(503))
    with pytest.raises(AdjudicationError, match=r"主用.*503.*备用.*429"):
        await FailoverAdjudicator(
            down, _adj(_spec(name="B"), lambda _r: httpx.Response(429))
        ).answer(INP)
    with pytest.raises(ProviderError, match="503"):
        await FailoverAdjudicator(down).answer(INP)


async def test_open_helpers_close_clients() -> None:
    transport = httpx.MockTransport(lambda _r: _chat())
    async with open_provider(_spec(), transport=transport) as p:
        assert (await p.assess(INP)).verdict == "yes"
    assert p._client.is_closed
    async with open_adjudicator(_spec(), _spec(name="B"), summary_language="English",
                                transport=transport) as f:  # fmt: skip
        assert (await f.answer(INP)).provider == "DeepSeek"
    assert f.primary._client.is_closed and f.backup is not None and f.backup._client.is_closed


CODE_INP = CodeInput(
    organization="Example Development Bank", aliases=("EDB",), official_domains=("edb.example",),
    repo="acme/deploy", repo_meta=RepoMeta(owner="acme", owner_type="Organization"), hits=(),
    secrets=(SecretSample(ref="S1", rule="aws-access-token", file="config/app.env", line=2,
                          date="2026-09-20T00:00:00Z", context=("AWS=AKIA…[REDACTED:12345678]",)),
             SecretSample(ref="S2", rule="generic-api-key", file="tests/fixture.py", line=1, date="",
                          context=())),
    refs=(("S1", "a" * 64), ("S2", "b" * 64)),
)  # fmt: skip
CODE_ANSWER = (
    '{"secrets": [{"ref": "S1", "verdict": "real"}], "relation": "org", "confidence": 0.8,'
    ' "rationale": "r", "summary": "s"}'
)


async def test_code_input_uses_code_prompt_and_parser() -> None:
    seen: list[httpx.Request] = []
    ans = await _adj(_spec(), lambda _r: _chat(CODE_ANSWER), seen).answer(CODE_INP)
    assert isinstance(ans.assessment, CodeAssessment)
    assert ans.assessment.secrets == (("S1", "real"), ("S2", "unsure"))
    assert ans.assessment.relation == "org" and ans.assessment.verdict == "real"
    body = json.loads(seen[0].content)
    system, user = (m["content"] for m in body["messages"])
    assert "leaked in public code repositories" in system
    assert "[S1] rule=aws-access-token" in user and "a" * 64 not in user  # 指纹不外发


async def test_code_answer_in_text_format_fails() -> None:
    with pytest.raises(AdjudicationError):
        await _adj(_spec(), lambda _r: _chat(ANSWER)).answer(CODE_INP)


async def test_failover_passes_code_input() -> None:
    def primary(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    adj = FailoverAdjudicator(
        _adj(_spec(), primary), _adj(_spec(id=2), lambda _r: _chat(CODE_ANSWER))
    )
    assert isinstance((await adj.answer(CODE_INP)).assessment, CodeAssessment)
