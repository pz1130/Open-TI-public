import io
from collections.abc import Callable
from typing import Any

import httpx
from PIL import Image, ImageDraw

from opti.core.config import ProjectRules
from opti.core.social import Profile
from opti.enrichers.social_mastodon import enricher as mod
from opti.sdk.testing import make_context

# 录制自 mastodon.social（2026-10-14），只保留用到的字段
ACCOUNT = {
    "id": "13179",
    "username": "Mastodon",
    "acct": "Mastodon",
    "display_name": "Mastodon",
    "created_at": "2016-11-23T00:00:00.000Z",
    "note": "<p>Our mission is to connect the world.</p><p>This is the primary account &amp; more.</p>",
    "url": "https://mastodon.social/@Mastodon",
    "uri": "https://mastodon.social/users/Mastodon",
    "avatar_static": "https://files.mastodon.social/accounts/avatars/000/013/179/original/b4ce.png",
    "followers_count": 878930,
}
REMOTE = {
    **ACCOUNT,
    "username": "sbrank",
    "acct": "sbrank@other.example",
    "url": "https://other.example/@sbrank",
    "uri": "https://other.example/users/sbrank",
    "avatar_static": "https://mastodon.social/avatars/original/missing.png",
}


async def _run(
    rules: ProjectRules,
    handler: Callable[[httpx.Request], httpx.Response],
    entity_type: str,
    value: str,
    config: dict[str, object] | None = None,
) -> dict[str, Any]:
    ctx = make_context(rules, connector_id="social_mastodon", handler=handler)
    try:
        return await mod.MastodonEnricher(ctx, config or {}).enrich(entity_type, value)
    finally:
        await ctx.http().aclose()


async def test_lookup_on_the_accounts_own_instance(sbr_rules: ProjectRules) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "mastodon.social"
        assert request.url.path == "/api/v1/accounts/lookup"
        assert request.url.params["acct"] == "mastodon"
        return httpx.Response(200, json=ACCOUNT)

    result = await _run(sbr_rules, respond, "social_profile", "mastodon@mastodon.social")
    profile = Profile.from_json(result["profile"])
    assert profile == Profile(
        platform_id="https://mastodon.social/users/Mastodon",
        handle="mastodon@mastodon.social",
        display_name="Mastodon",
        profile_url="https://mastodon.social/@Mastodon",
        registered_at=profile.registered_at if profile else None,
        bio="Our mission is to connect the world. This is the primary account & more.",
        avatar_url="https://files.mastodon.social/accounts/avatars/000/013/179/original/b4ce.png",
    )
    assert "followers_count" not in str(result)


async def test_missing_account_is_not_found_and_suspended_is_flagged(
    sbr_rules: ProjectRules,
) -> None:
    gone = await _run(
        sbr_rules,
        lambda _: httpx.Response(404, json={"error": "Record not found"}),
        "social_profile",
        "x@mastodon.social",
    )
    assert gone == {"not_found": True}
    gone = await _run(
        sbr_rules, lambda _: httpx.Response(410), "social_profile", "x@mastodon.social"
    )
    assert gone == {"not_found": True}
    suspended = await _run(
        sbr_rules,
        lambda _: httpx.Response(200, json={**ACCOUNT, "suspended": True}),
        "social_profile",
        "mastodon@mastodon.social",
    )
    profile = Profile.from_json(suspended["profile"])
    assert profile is not None and profile.suspended


async def test_search_each_configured_instance_without_token(sbr_rules: ProjectRules) -> None:
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        assert request.url.path == "/api/v2/search"
        assert request.url.params["type"] == "accounts"
        assert request.url.params["q"] == "sbrank"
        assert request.url.params["limit"] == "40"
        assert "resolve" not in request.url.params
        assert "authorization" not in request.headers
        if request.url.host == "down.example":
            return httpx.Response(503)
        return httpx.Response(200, json={"accounts": [REMOTE, {"uri": 5}, "junk"]})

    result = await _run(
        sbr_rules,
        respond,
        "social_search",
        "sbrank",
        {"instances": ["mastodon.social", "down.example"]},
    )
    assert sorted(set(seen)) == ["down.example", "mastodon.social"]
    assert result["failed_instances"] == 1
    profiles = [Profile.from_json(p) for p in result["profiles"]]
    assert [p.handle for p in profiles if p] == ["sbrank@other.example"]
    assert profiles[0] is not None and profiles[0].avatar_url is None  # 默认头像不算头像


async def test_local_accounts_get_the_instance_suffix(sbr_rules: ProjectRules) -> None:
    result = await _run(
        sbr_rules, lambda _: httpx.Response(200, json={"accounts": [ACCOUNT]}), "social_search", "x"
    )
    assert [p["handle"] for p in result["profiles"]] == ["mastodon@mastodon.social"]


async def test_denied_instance_is_skipped_for_an_hour(sbr_rules: ProjectRules) -> None:
    calls = 0

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(403)

    ctx = make_context(sbr_rules, connector_id="social_mastodon", handler=respond)
    try:
        enricher = mod.MastodonEnricher(ctx, {"instances": ["mastodon.social"]})
        first = await enricher.enrich("social_search", "a")
        second = await enricher.enrich("social_search", "b")
    finally:
        await ctx.http().aclose()
    assert first == {"error": "all_instances_failed", "failed_instances": 1}
    assert second == {"error": "all_instances_failed", "failed_instances": 1}
    assert calls == 1  # 401/403 后本小时不再请求，不尝试绕过限制


async def test_avatar_only_from_configured_instances(sbr_rules: ProjectRules) -> None:
    image = Image.new("RGB", (64, 64), "white")
    ImageDraw.Draw(image).rectangle((0, 0, 31, 63), fill="black")
    buf = io.BytesIO()
    image.save(buf, format="PNG")

    ok = await _run(
        sbr_rules,
        lambda _: httpx.Response(200, content=buf.getvalue()),
        "social_avatar",
        "https://files.mastodon.social/a.png",
    )
    assert set(ok) == {"dhash", "sha256"}

    def never(_: httpx.Request) -> httpx.Response:
        raise AssertionError("不应访问")

    for url in (
        "https://other.example/a.png",
        "https://evilmastodon.social/a.png",
        "http://files.mastodon.social/a.png",
    ):
        assert await _run(sbr_rules, never, "social_avatar", url) == {
            "error": "avatar_host_not_allowed"
        }


async def test_invalid_instance_config_is_rejected(sbr_rules: ProjectRules) -> None:
    def never(_: httpx.Request) -> httpx.Response:
        raise AssertionError("不应访问")

    result = await _run(
        sbr_rules, never, "social_search", "x", {"instances": ["http://bad/", "127.0.0.1"]}
    )
    assert result == {"error": "no_instances"}


async def test_profile_link_must_stay_on_the_accounts_own_server(sbr_rules: ProjectRules) -> None:
    # 远程账号可以把 url 填成任意网址（如本机构官网），只认账号所在服务器上的链接
    spoofed = {**REMOTE, "url": "https://www.sbr.int/"}
    result = await _run(
        sbr_rules, lambda _: httpx.Response(200, json={"accounts": [spoofed]}), "social_search", "x"
    )
    assert [p["profile_url"] for p in result["profiles"]] == ["https://other.example/users/sbrank"]
    kept = await _run(
        sbr_rules, lambda _: httpx.Response(200, json={"accounts": [REMOTE]}), "social_search", "x"
    )
    assert [p["profile_url"] for p in kept["profiles"]] == ["https://other.example/@sbrank"]
