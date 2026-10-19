import pytest

from opti.llm_presets import (
    BY_KEY,
    PRESETS,
    check_base_url,
    check_proxy,
    provider_base_url,
    proxy_hint,
)


def test_catalog() -> None:
    assert len(BY_KEY) == len(PRESETS) == 18
    groups = [p.group for p in PRESETS]
    assert (groups.count("international"), groups.count("domestic"), groups.count("local")) == (
        7,
        9,
        2,
    )
    assert {p.key for p in PRESETS if p.group == "local"} == {"selfhosted", "custom"}
    claude = BY_KEY["anthropic"]
    assert (claude.protocol, claude.auth) == ("anthropic", "x-api-key")
    assert BY_KEY["azure_openai"].auth == "api-key" and BY_KEY["azure_openai"].list_models == "no"
    assert BY_KEY["doubao"].model == "" and BY_KEY["doubao"].list_models == "no"
    assert BY_KEY["openai"].temperature is None and BY_KEY["deepseek"].temperature == 0
    for p in PRESETS:
        assert p.key_required == (p.group != "local") and p.insecure_http == (p.group == "local")
        assert p.public()["key"] == p.key
        if p.base_url and "{" not in p.base_url:
            assert check_base_url(p, p.base_url) == p.base_url  # 预设地址本身合格


def test_base_url_rules() -> None:
    deepseek, local = BY_KEY["deepseek"], BY_KEY["selfhosted"]
    assert (
        check_base_url(deepseek, " https://api.deepseek.com/v1/ ") == "https://api.deepseek.com/v1"
    )
    assert check_base_url(local, "http://vllm:8000/v1") == "http://vllm:8000/v1"
    with pytest.raises(ValueError, match="https"):
        check_base_url(deepseek, "http://api.deepseek.com/v1")
    with pytest.raises(ValueError, match="placeholder"):
        check_base_url(BY_KEY["azure_openai"], BY_KEY["azure_openai"].base_url)
    for bad in ("https://x.example/v1?a=1", "https://x.example/v1#f", "https://u:p@x.example/v1",
                "ftp://x.example", "https:///v1", "https://" + "a" * 520):  # fmt: skip
        with pytest.raises(ValueError):
            check_base_url(local, bad)


def test_proxy_rules_and_hint() -> None:
    url = "socks5://user:" + "pw" + "@proxy.internal:1080"
    assert check_proxy(f" {url} ") == url
    assert proxy_hint(url) == "socks5://proxy.internal:1080"
    assert proxy_hint("http://[2001:db8::1]:3128") == "http://[2001:db8::1]:3128"
    assert proxy_hint("https://proxy.example") == "https://proxy.example"
    for bad in ("ftp://p:21", "socks5://", "http://p:99999", "http://p/path", "http://p?x=1"):
        with pytest.raises(ValueError):
            check_proxy(bad)


def test_minimax_preset_uses_messages_api() -> None:
    p = BY_KEY["minimax"]
    assert (p.protocol, p.auth) == ("anthropic", "bearer")
    assert p.base_url == "https://api.minimax.cn/anthropic/v1"
    assert p.model == "MiniMax-M2" and p.temperature == 1
    assert not p.json_mode and p.list_models == "no"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://api.minimaxi.com/v1", "https://api.minimax.cn/anthropic/v1"),
        ("https://api.minimaxi.com/anthropic", "https://api.minimax.cn/anthropic/v1"),
        ("https://api.minimax.cn", "https://api.minimax.cn/anthropic/v1"),
        (" https://api.minimax.cn/anthropic/ ", "https://api.minimax.cn/anthropic/v1"),
        ("https://api.minimax.cn/anthropic/v1", "https://api.minimax.cn/anthropic/v1"),
        ("https://api.minimax.cn/anthropic/v1/messages", "https://api.minimax.cn/anthropic/v1"),
        ("https://api.minimax.cn/v1/chat/completions", "https://api.minimax.cn/anthropic/v1"),
        ("https://api.minimax.io/v1", "https://api.minimax.io/anthropic/v1"),
        ("https://api.minimax.io/anthropic", "https://api.minimax.io/anthropic/v1"),
        ("https://api.minimax.io/anthropic/v1/messages", "https://api.minimax.io/anthropic/v1"),
        ("https://relay.example/prefix/v1", "https://relay.example/prefix/v1"),
        ("https://relay.example/prefix/anthropic", "https://relay.example/prefix/anthropic/v1"),
        (
            "https://relay.example/prefix/anthropic/v1/messages",
            "https://relay.example/prefix/anthropic/v1",
        ),
        ("https://api.minimax.cn/unknown/v1", "https://api.minimax.cn/unknown/v1"),
    ],
)
def test_minimax_address_compatibility(url: str, expected: str) -> None:
    assert check_base_url(BY_KEY["minimax"], url) == expected
    assert provider_base_url("minimax", url) == expected
    assert provider_base_url("minimax", expected) == expected


def test_minimax_normalization_does_not_bypass_url_validation() -> None:
    for bad in (
        "https://user:private@api.minimax.cn/anthropic",
        "https://api.minimax.cn/anthropic?key=private",
        "https://api.minimax.cn/anthropic#fragment",
        "https://api.minimax.cn:invalid/v1",
        "http://api.minimax.cn/v1",
    ):
        with pytest.raises(ValueError):
            check_base_url(BY_KEY["minimax"], bad)
    url = "https://api.minimax.cn/v1"
    assert check_base_url(BY_KEY["custom"], url) == url
    assert provider_base_url("custom", url) == url
