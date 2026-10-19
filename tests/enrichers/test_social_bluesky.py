import hashlib
import io
from collections.abc import Callable
from typing import Any

import httpx
from PIL import Image, ImageDraw

from opti.core.config import ProjectRules
from opti.core.social import Profile
from opti.enrichers.social_bluesky import enricher as mod
from opti.sdk.testing import make_context

# 录制自 public.api.bsky.app（2026-10-14），只保留用到的字段
ACTOR = {
    "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
    "handle": "bsky.app",
    "displayName": "Bluesky",
    "avatar": "https://cdn.bsky.app/img/avatar/plain/did:plc:z72i7hdynmk6r22z27h6tvur/bafkrei@jpeg",
    "createdAt": "2023-04-12T04:53:57.057Z",
    "description": "official Bluesky account (check username👆)",
    "followersCount": 35251237,
    "labels": [],
}


def _png() -> bytes:
    image = Image.new("RGB", (64, 64), "white")
    ImageDraw.Draw(image).rectangle((0, 0, 31, 63), fill="black")
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


async def _run(
    rules: ProjectRules,
    handler: Callable[[httpx.Request], httpx.Response],
    entity_type: str,
    value: str,
    config: dict[str, object] | None = None,
) -> dict[str, Any]:
    ctx = make_context(rules, connector_id="social_bluesky", handler=handler)
    try:
        return await mod.BlueskyEnricher(ctx, config or {}).enrich(entity_type, value)
    finally:
        await ctx.http().aclose()


async def test_profile_keeps_only_decision_fields(sbr_rules: ProjectRules) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "public.api.bsky.app"
        assert request.url.path == "/xrpc/app.bsky.actor.getProfile"
        assert request.url.params["actor"] == "bsky.app"
        return httpx.Response(200, json=ACTOR)

    result = await _run(sbr_rules, respond, "social_profile", "bsky.app")
    profile = Profile.from_json(result["profile"])
    assert profile is not None
    assert profile.platform_id == "did:plc:z72i7hdynmk6r22z27h6tvur"
    assert profile.profile_url == "https://bsky.app/profile/did:plc:z72i7hdynmk6r22z27h6tvur"
    assert profile.registered_at is not None and profile.registered_at.year == 2023
    assert "followersCount" not in str(result)  # 不保存粉丝数等无关资料


async def test_missing_or_taken_down_profile_is_not_found(sbr_rules: ProjectRules) -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "InvalidRequest", "message": "Profile not found"})

    assert await _run(sbr_rules, respond, "social_profile", "gone.bsky.social") == {
        "not_found": True
    }


async def test_taken_down_label_marks_profile_suspended(sbr_rules: ProjectRules) -> None:
    actor = {**ACTOR, "labels": [{"val": "!takedown"}]}
    result = await _run(
        sbr_rules, lambda _: httpx.Response(200, json=actor), "social_profile", "bsky.app"
    )
    profile = Profile.from_json(result["profile"])
    assert profile is not None and profile.suspended


async def test_search_parses_actors_and_skips_malformed(sbr_rules: ProjectRules) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/xrpc/app.bsky.actor.searchActors"
        assert request.url.params["q"] == "Sample Brand"
        assert request.url.params["limit"] == "50"
        return httpx.Response(
            200,
            json={
                "actors": [
                    ACTOR,
                    {"did": 1, "handle": "x.bsky.social"},
                    {**ACTOR, "did": "did:plc:other", "handle": "handle.invalid"},
                    "junk",
                ]
            },
        )

    result = await _run(sbr_rules, respond, "social_search", "Sample Brand")
    assert [p["handle"] for p in result["profiles"]] == ["bsky.app"]


async def test_custom_appview_url(sbr_rules: ProjectRules) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "appview.example.org"
        return httpx.Response(200, json={"actors": []})

    result = await _run(
        sbr_rules, respond, "social_search", "sbr", {"appview_url": "https://appview.example.org"}
    )
    assert result == {"profiles": []}


async def test_search_failure_and_bad_body_are_errors(sbr_rules: ProjectRules) -> None:
    assert "error" in await _run(sbr_rules, lambda _: httpx.Response(403), "social_search", "sbr")
    assert await _run(
        sbr_rules, lambda _: httpx.Response(200, json=[1]), "social_search", "sbr"
    ) == {"error": "invalid_response"}


async def test_rate_limited_search_retries_once_then_reports(sbr_rules: ProjectRules) -> None:
    calls = 0

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "5"})

    assert "error" in await _run(sbr_rules, respond, "social_search", "sbr")
    assert calls == 2


async def test_avatar_hashes_in_memory_from_bluesky_cdn_only(sbr_rules: ProjectRules) -> None:
    data = _png()

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "cdn.bsky.app"
        return httpx.Response(200, content=data)

    result = await _run(
        sbr_rules, respond, "social_avatar", "https://cdn.bsky.app/img/avatar/plain/x"
    )
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert isinstance(result["dhash"], str) and len(result["dhash"]) == 16

    def never(_: httpx.Request) -> httpx.Response:
        raise AssertionError("不应访问非平台图片主机")

    for url in (
        "https://169.254.169.254/latest",
        "http://cdn.bsky.app/x",
        "https://cdn.bsky.app.evil.com/x",
    ):
        assert await _run(sbr_rules, never, "social_avatar", url) == {
            "error": "avatar_host_not_allowed"
        }


async def test_avatar_rejects_large_or_unsupported_images(sbr_rules: ProjectRules) -> None:
    big = await _run(
        sbr_rules,
        lambda _: httpx.Response(200, content=b"\0" * (1024 * 1024 + 1)),
        "social_avatar",
        "https://cdn.bsky.app/a",
    )
    assert "error" in big
    gif = await _run(
        sbr_rules,
        lambda _: httpx.Response(200, content=b"GIF89a" + b"\0" * 100),
        "social_avatar",
        "https://cdn.bsky.app/a",
    )
    assert gif == {"error": "unsupported_image"}


async def test_unknown_type_is_an_error(sbr_rules: ProjectRules) -> None:
    assert await _run(sbr_rules, lambda _: httpx.Response(500), "domain", "x") == {
        "error": "unsupported_type"
    }
