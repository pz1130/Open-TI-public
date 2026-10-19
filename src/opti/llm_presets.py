"""大模型供应商预设（设计 2026-10-10-llm-providers）。

地址、模型、JSON 模式与温度只是新建时的默认值，都可以改（如百炼国际站、Kimi .ai 域名）。
默认模型名按各家官方文档核实（2026-10）。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

Group = Literal["international", "domestic", "local"]
WireProtocol = Literal["anthropic", "openai"]
Auth = Literal["x-api-key", "bearer", "api-key"]
ListModels = Literal["yes", "try", "no"]
MAX_URL = 512


@dataclass(frozen=True)
class Preset:
    key: str
    name: str
    group: Group
    protocol: WireProtocol
    auth: Auth
    base_url: str
    model: str
    json_mode: bool
    temperature: float | None
    list_models: ListModels
    key_required: bool = True
    insecure_http: bool = False

    def public(self) -> dict[str, Any]:
        return asdict(self)


def _p(
    key: str,
    name: str,
    group: Group,
    base_url: str,
    model: str,
    *,
    protocol: WireProtocol = "openai",
    auth: Auth = "bearer",
    json_mode: bool = True,
    temperature: float | None = 0.0,
    list_models: ListModels = "yes",
) -> Preset:
    local = group == "local"
    return Preset(
        key,
        name,
        group,
        protocol,
        auth,
        base_url,
        model,
        json_mode,
        temperature,
        list_models,
        key_required=not local,
        insecure_http=local,
    )


PRESETS: tuple[Preset, ...] = (
    # 国际
    _p(
        "openai",
        "OpenAI",
        "international",
        "https://api.openai.com/v1",
        "gpt-5-mini",
        temperature=None,
    ),  # GPT-5 / o 系列只接受默认温度
    _p(
        "anthropic",
        "Anthropic Claude",
        "international",
        "https://api.anthropic.com/v1",
        "claude-sonnet-5-5",
        protocol="anthropic",
        auth="x-api-key",
        json_mode=False,
    ),
    _p(
        "gemini",
        "Google Gemini",
        "international",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-flash-latest",
    ),
    _p(
        "azure_openai",
        "Azure OpenAI",
        "international",
        "https://{resource}.openai.azure.com/openai/v1",
        "",
        auth="api-key",
        temperature=None,
        list_models="no",
    ),  # 模型字段填部署名
    _p("mistral", "Mistral", "international", "https://api.mistral.ai/v1", "mistral-small-latest"),
    _p("xai", "xAI Grok", "international", "https://api.x.ai/v1", "grok-4"),
    _p(
        "openrouter",
        "OpenRouter",
        "international",
        "https://openrouter.ai/api/v1",
        "openai/gpt-5-mini",
        json_mode=False,
    ),
    # 国内
    _p("deepseek", "DeepSeek", "domestic", "https://api.deepseek.com/v1", "deepseek-flash"),
    _p(
        "qwen",
        "通义千问（阿里云百炼）",
        "domestic",
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "qwen-plus",
    ),
    _p(
        "zhipu",
        "智谱 GLM",
        "domestic",
        "https://open.bigmodel.cn/api/paas/v4",
        "glm-4.6",
        list_models="try",
    ),
    _p("moonshot", "Kimi（月之暗面）", "domestic", "https://api.moonshot.cn/v1", "kimi-latest"),
    _p(
        "doubao",
        "豆包（火山方舟）",
        "domestic",
        "https://ark.cn-beijing.volces.com/api/v3",
        "",
        list_models="no",
    ),  # 模型字段填模型或接入点 ID
    _p(
        "qianfan",
        "文心（百度千帆）",
        "domestic",
        "https://qianfan.baidubce.com/v2",
        "ernie-4.5-turbo-128k",
        json_mode=False,
        list_models="try",
    ),
    _p(
        "hunyuan",
        "混元（腾讯）",
        "domestic",
        "https://tokenhub.tencentmaas.com/v1",
        "hy3-preview",
        json_mode=False,
        list_models="try",
    ),
    _p(
        "minimax",
        "MiniMax",
        "domestic",
        "https://api.minimax.cn/anthropic/v1",
        "MiniMax-M2",
        protocol="anthropic",
        json_mode=False,
        temperature=1.0,
        list_models="no",
    ),
    _p(
        "siliconflow",
        "硅基流动",
        "domestic",
        "https://api.siliconflow.cn/v1",
        "deepseek-ai/DeepSeek-V3",
    ),
    # 本地
    _p("selfhosted", "自托管（vLLM / Ollama）", "local", "", ""),
    _p("custom", "自定义 OpenAI 兼容", "local", "", "", list_models="try"),
)
BY_KEY: dict[str, Preset] = {p.key: p for p in PRESETS}


def provider_base_url(preset: str, url: str) -> str:
    """Normalize MiniMax SDK roots and legacy official URLs, keeping relay prefixes intact."""
    url = url.strip().rstrip("/")
    if preset != "minimax":
        return url
    parts = urlsplit(url)
    official = {
        "api.minimaxi.com": "api.minimax.cn",
        "api.minimax.cn": "api.minimax.cn",
        "api.minimax.io": "api.minimax.io",
    }
    known_paths = {
        "",
        "/v1",
        "/anthropic",
        "/anthropic/v1",
        "/anthropic/v1/messages",
        "/v1/chat/completions",
    }
    if (
        parts.scheme == "https"
        and parts.hostname in official
        and parts.port in (None, 443)
        and parts.path in known_paths
        and not (parts.username or parts.password or parts.query or parts.fragment)
    ):
        return f"https://{official[parts.hostname]}/anthropic/v1"
    if parts.path.endswith("/anthropic"):
        return url + "/v1"
    if parts.path.endswith("/anthropic/v1/messages"):
        return url.removesuffix("/messages")
    return url


def check_base_url(preset: Preset, url: str) -> str:
    """返回去掉首尾空白与末尾 / 的地址；不合格抛 ValueError（英文，接口直接作为 422 详情）。"""
    url = url.strip().rstrip("/")
    if "{" in url or "}" in url:
        raise ValueError("base_url still contains a placeholder such as {resource}")
    if len(url) > MAX_URL:
        raise ValueError("base_url is too long")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  # 端口非法时抛 ValueError
    except ValueError:
        raise ValueError("base_url is not a valid URL") from None
    allowed = ("https", "http") if preset.insecure_http else ("https",)
    if parts.scheme not in allowed:
        raise ValueError(
            "base_url must use http or https" if preset.insecure_http else "base_url must use https"
        )
    if not parts.hostname:
        raise ValueError("base_url must include a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("base_url must not contain credentials")
    if parts.query or parts.fragment:
        raise ValueError("base_url must not contain a query or fragment")
    return provider_base_url(preset.key, url)


def check_proxy(url: str) -> str:
    url = url.strip()
    if len(url) > MAX_URL:
        raise ValueError("proxy is too long")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018
    except ValueError:
        raise ValueError("proxy is not a valid URL") from None
    if parts.scheme not in ("http", "https", "socks5"):
        raise ValueError("proxy must use http, https or socks5")
    if not parts.hostname:
        raise ValueError("proxy must include a host")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("proxy must not contain a path, query or fragment")
    return url


def proxy_hint(url: str) -> str:
    """去掉账号密码后的代理地址，可以显示与写入审计。"""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}"
