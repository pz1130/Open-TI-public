"""大模型供应商调用（设计文档 9.4；设计 2026-10-10-llm-providers）。

两种协议：Anthropic Messages（含 MiniMax）与 OpenAI chat/completions。
输入只能是 PublicInput 或 CodeInput（都已经过外发过滤）。任何调用或解析错误都转成 AdjudicationError，
消息里只有状态码或错误类别，不含密钥与响应正文。
专用客户端不跟随重定向（自定义鉴权头会随跳转带到别的主机），也不读 HTTPS_PROXY 等环境变量。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from opti.core.adjudication import (
    AdjudicationError,
    Assessment,
    PublicInput,
    build_prompt,
    parse_assessment,
)
from opti.core.code_adjudication import (
    CodeAssessment,
    CodeInput,
    build_code_prompt,
    parse_code_assessment,
)
from opti.core.secret_guard import SecretEgressBlocked, assert_no_secret, mask_deep
from opti.llm_presets import provider_base_url
from opti.sdk.http import default_user_agent

ANTHROPIC_VERSION = "2023-06-01"
MAX_TOKENS = 600
MINIMAX_MAX_TOKENS = 8192  # Includes reasoning tokens; 600 may yield thinking without any text.
MAX_RESPONSE_BYTES = 2_000_000
MAX_MODELS = 500
FAILOVER_AFTER = 3
UNSUPPORTED_LIST = "该供应商不支持在线获取模型列表，请手填"


@dataclass(frozen=True)
class ProviderSpec:
    """解密后的运行时配置。api_key 与 proxy 不进 repr，避免出现在日志与异常里。"""

    id: int
    name: str
    preset: str
    protocol: str  # anthropic / openai
    auth: str  # x-api-key / bearer / api-key
    base_url: str
    model: str
    api_key: str | None = field(default=None, repr=False)
    proxy: str | None = field(default=None, repr=False)
    json_mode: bool = True
    temperature: float | None = 0.0
    timeout: float = 60.0


Input = PublicInput | CodeInput


@dataclass(frozen=True)
class Answer:
    assessment: Assessment | CodeAssessment
    backend: str  # 预设键
    model: str
    provider: str  # 显示名


class Adjudicator(Protocol):
    backend: str
    model: str
    provider: str

    async def answer(self, inp: Input) -> Answer: ...


class ProviderError(AdjudicationError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _minimax_error(status: int, doc: Any) -> str:
    """Only return local hints and known codes, never the vendor's message or trace body."""
    hints = {
        400: "请求参数不兼容，请检查模型名称和参数",
        401: "API Key 无效或与国内/国际站点不匹配",
        403: "API Key 权限不足或账户访问受限",
        404: "接口或模型不存在，请检查接口地址与模型名",
        422: "请求参数不兼容，请检查模型名称和参数",
        429: "频率或额度受限，请检查账户用量后重试",
    }
    codes = {
        1001: "请求超时，请稍后重试",
        1002: "请求频率超限，请稍后重试",
        1004: hints[401],
        1008: "账户余额不足，请检查账户余额",
        1039: "生成长度超出限制",
        2013: hints[400],
        2049: hints[401],
        2056: "套餐额度受限，请等待额度恢复后重试",
    }
    code = None
    if isinstance(doc, dict):
        base = doc.get("base_resp")
        if isinstance(base, dict) and type(base.get("status_code")) is int:
            code = base["status_code"]
    hint = codes.get(code) if code is not None else None
    hint = hint or hints.get(status, "服务暂时不可用，请稍后重试")
    suffix = f"，错误码 {code}" if code in codes else ""
    return f"MiniMax 模型接口调用失败（HTTP {status}{suffix}）：{hint}"


def make_client(
    spec: ProviderSpec, transport: httpx.AsyncBaseTransport | None = None
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=transport or httpx.AsyncHTTPTransport(proxy=spec.proxy, trust_env=False),
        timeout=spec.timeout,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": default_user_agent()},
    )


class ProviderAdjudicator:
    def __init__(
        self, spec: ProviderSpec, client: httpx.AsyncClient, *, summary_language: str = "Chinese"
    ) -> None:
        self.spec, self._client, self._lang = spec, client, summary_language
        self.backend, self.model, self.provider = spec.preset, spec.model, spec.name

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.spec.protocol == "anthropic":
            headers["anthropic-version"] = ANTHROPIC_VERSION
        key = self.spec.api_key
        if key:
            if self.spec.auth == "x-api-key":
                headers["x-api-key"] = key
            elif self.spec.auth == "api-key":
                headers["api-key"] = key
            else:
                headers["Authorization"] = f"Bearer {key}"
        return headers

    async def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = provider_base_url(self.spec.preset, self.spec.base_url) + path
        # 设计文档 2.3：送往大模型的内容先遮蔽凭据，再做一次硬拦截
        body = mask_deep(body) if body is not None else None
        try:
            assert_no_secret("llm", url=url, body=body, headers=self._headers())
        except SecretEgressBlocked as exc:
            raise ProviderError(f"已拦截发往模型的请求（{exc.reason}）") from None
        try:
            resp = await self._client.request(method, url, json=body, headers=self._headers())
        except httpx.TimeoutException:
            raise ProviderError("模型接口调用超时") from None
        except (httpx.HTTPError, httpx.InvalidURL):
            raise ProviderError("模型接口调用失败（网络错误）") from None
        status = resp.status_code
        if 300 <= status < 400:
            raise ProviderError(f"接口返回重定向（{status}），请检查地址", status)
        if status >= 400 and self.spec.preset == "minimax":
            try:
                error_doc = resp.json() if len(resp.content) <= MAX_RESPONSE_BYTES else None
            except ValueError:
                error_doc = None
            raise ProviderError(_minimax_error(status, error_doc), status)
        if status >= 400:
            raise ProviderError(f"模型接口调用失败（{status}）", status)
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ProviderError("模型接口返回内容过大")
        try:
            doc = resp.json()
        except ValueError:
            raise ProviderError("模型接口返回的不是 JSON") from None
        if self.spec.preset == "minimax" and isinstance(doc, dict):
            base = doc.get("base_resp")
            failed = isinstance(base, dict) and base.get("status_code") not in (None, 0)
            if failed or doc.get("type") == "error" or isinstance(doc.get("error"), dict):
                raise ProviderError(_minimax_error(status, doc), status)
        return doc

    async def answer(self, inp: Input) -> Answer:
        if isinstance(inp, CodeInput):
            system, user = build_code_prompt(inp, summary_language=self._lang)
        else:
            system, user = build_prompt(inp, summary_language=self._lang)
        body: dict[str, Any]
        if self.spec.protocol == "anthropic":
            body = {"model": self.model, "max_tokens": MINIMAX_MAX_TOKENS if self.spec.preset == "minimax" else MAX_TOKENS, "system": system,
                    "messages": [{"role": "user", "content": user}]}  # fmt: skip
            if self.spec.temperature is not None:
                body["temperature"] = self.spec.temperature
            doc = await self._call("POST", "/messages", body)
            if isinstance(doc, dict) and doc.get("stop_reason") == "max_tokens":
                raise ProviderError("模型生成达到长度上限（包含思考过程），未返回完整研判结果")
            blocks = doc.get("content") if isinstance(doc, dict) else None
            text = "".join(
                str(b.get("text") or "")
                for b in (blocks if isinstance(blocks, list) else [])
                if isinstance(b, dict) and b.get("type") == "text"
            )
        else:
            body = {"model": self.model, "messages": [
                {"role": "system", "content": system}, {"role": "user", "content": user}]}  # fmt: skip
            if self.spec.temperature is not None:
                body["temperature"] = self.spec.temperature
            if self.spec.json_mode:
                body["response_format"] = {"type": "json_object"}
            doc = await self._call("POST", "/chat/completions", body)
            try:
                content = doc["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                raise ProviderError("模型接口返回格式不对") from None
            text = str(content or "")
        assessment = (
            parse_code_assessment(text, [s.ref for s in inp.secrets])
            if isinstance(inp, CodeInput)
            else parse_assessment(text)
        )
        return Answer(assessment, self.backend, self.model, self.provider)

    async def assess(self, inp: PublicInput) -> Assessment:
        return _text((await self.answer(inp)).assessment)

    async def list_models(self) -> list[str]:
        try:
            doc = await self._call("GET", "/models")
        except ProviderError as e:
            if e.status in (404, 405):
                raise ProviderError(UNSUPPORTED_LIST, e.status) from None
            raise
        data = doc.get("data") if isinstance(doc, dict) else None
        if not isinstance(data, list):
            raise ProviderError(UNSUPPORTED_LIST)
        ids = {
            m["id"]
            for m in data
            if isinstance(m, dict) and isinstance(m.get("id"), str) and 0 < len(m["id"]) <= 128
        }
        return sorted(ids)[:MAX_MODELS]


class FailoverAdjudicator:
    """先调主用，失败改调备用；同一实例中主用连续失败 FAILOVER_AFTER 次后直接走备用。

    研判 worker 每轮新建实例，所以下一轮会重新先试主用。
    """

    def __init__(
        self, primary: ProviderAdjudicator, backup: ProviderAdjudicator | None = None
    ) -> None:
        self.primary, self.backup = primary, backup
        self.backend, self.model, self.provider = primary.backend, primary.model, primary.provider
        self._failures = 0

    async def answer(self, inp: Input) -> Answer:
        if self.backup is None:
            return await self.primary.answer(inp)
        first: str | None = None
        if self._failures < FAILOVER_AFTER:
            try:
                result = await self.primary.answer(inp)
            except AdjudicationError as e:
                self._failures += 1
                first = str(e)
            else:
                self._failures = 0
                return result
        try:
            return await self.backup.answer(inp)
        except AdjudicationError as e:
            head = f"主用：{first}" if first is not None else "主用已连续失败"
            raise AdjudicationError(f"{head}；备用：{e}") from None

    async def assess(self, inp: PublicInput) -> Assessment:
        return _text((await self.answer(inp)).assessment)


def _text(assessment: Assessment | CodeAssessment) -> Assessment:
    assert isinstance(assessment, Assessment)  # 文本输入只会得到文本结论
    return assessment


@asynccontextmanager
async def open_provider(
    spec: ProviderSpec,
    *,
    summary_language: str = "Chinese",
    transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[ProviderAdjudicator]:
    client = make_client(spec, transport)
    try:
        yield ProviderAdjudicator(spec, client, summary_language=summary_language)
    finally:
        await client.aclose()


@asynccontextmanager
async def open_adjudicator(
    primary: ProviderSpec,
    backup: ProviderSpec | None,
    *,
    summary_language: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[FailoverAdjudicator]:
    async with open_provider(primary, summary_language=summary_language, transport=transport) as p:
        if backup is None:
            yield FailoverAdjudicator(p)
            return
        async with open_provider(
            backup, summary_language=summary_language, transport=transport
        ) as b:
            yield FailoverAdjudicator(p, b)
