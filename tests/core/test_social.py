from datetime import UTC, datetime, timedelta

import pytest

from opti.core.scoring import AccountFacts
from opti.core.social import (
    Avatar,
    Profile,
    Protected,
    compare,
    excluded,
    normalize_handle,
    normalize_name,
    search_queries,
)

NOW = datetime(2026, 10, 14, tzinfo=UTC)
# 区分力足够的两个 dHash：汉明距离 3
OFFICIAL = Avatar("f0f0f0f00f0f0f0f", "a" * 64)
NEAR = Avatar("f0f0f0f00f0f0f08", "b" * 64)


def _profile(**kw: object) -> Profile:
    base: dict[str, object] = {
        "platform_id": "did:plc:fake",
        "handle": "someone.bsky.social",
        "display_name": "Someone",
        "profile_url": "https://bsky.app/profile/did:plc:fake",
        "registered_at": None,
        "bio": "",
        "avatar_url": None,
    }
    base.update(kw)
    return Profile(**base)  # type: ignore[arg-type]


PROTECTED = Protected(
    platform="bluesky",
    handle="sbrank.bsky.social",
    platform_id="did:plc:official",
    display_name="Sample Brand",
    avatar=OFFICIAL,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Sample Brand", "samplebrand"),
        ("Sаmplе Brаnd 🏦", "samplebrand"),  # 西里尔 е 与 emoji
        ("SAMPLE_BRAND.", "samplebrand"),
        ("样本品牌（官方）", "样本品牌官方"),
    ],
)
def test_normalize_name_strips_homoglyphs_and_separators(raw: str, expected: str) -> None:
    assert normalize_name(raw) == expected


@pytest.mark.parametrize(
    ("platform", "raw", "expected"),
    [
        ("bluesky", "@SBRank.bsky.social", "sbrank.bsky.social"),
        ("bluesky", "news.sbr.int", "news.sbr.int"),
        ("mastodon", "@SBRank@Mastodon.Social", "sbrank@mastodon.social"),
    ],
)
def test_normalize_handle(platform: str, raw: str, expected: str) -> None:
    assert normalize_handle(platform, raw) == expected


@pytest.mark.parametrize(
    ("platform", "raw"),
    [
        ("bluesky", "sbrank"),
        ("bluesky", "bad_label.bsky.social"),
        ("bluesky", "1.2.3.4"),
        ("mastodon", "sbrank"),
        ("mastodon", "nd bank@mastodon.social"),
        ("mastodon", "sbrank@localhost"),
        ("x", "sbrank"),
    ],
)
def test_normalize_handle_rejects_invalid(platform: str, raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_handle(platform, raw)


def test_search_queries_use_names_and_extras_without_duplicates() -> None:
    assert search_queries(PROTECTED, ["样本银行", "sample brand", "x", ""]) == [
        "Sample Brand",
        "sbrank",
        "样本银行",
    ]


def test_search_queries_are_capped_at_seven() -> None:
    extras = [f"term {i}" for i in range(10)]
    assert len(search_queries(PROTECTED, extras)) == 7


def test_same_name_handle_avatar_and_fresh_claim() -> None:
    facts = compare(
        PROTECTED,
        _profile(
            handle="sbrank-official.bsky.social",
            display_name="Sample Brand",
            bio="Official account of the bank",
            registered_at=NOW - timedelta(days=3),
        ),
        NEAR,
        NOW,
    )
    assert facts == AccountFacts(
        display="same", handle="contains", avatar_distance=3, bio_claim=True, age_days=3
    )


def test_handle_within_two_edits_counts_as_same() -> None:
    facts = compare(PROTECTED, _profile(handle="sbramk.bsky.social", display_name="x"), None, NOW)
    assert facts.handle == "same"


def test_short_handles_need_an_exact_match() -> None:
    short = Protected("bluesky", "sbr.bsky.social", "did:plc:o", "SBR", None)
    assert (
        compare(short, _profile(handle="nab.bsky.social", display_name="z"), None, NOW).handle
        is None
    )
    assert (
        compare(short, _profile(handle="sbr.bsky.social", display_name="z"), None, NOW).handle
        == "same"
    )
    # 不到 4 个字也不按“包含”算，避免 sbr 命中大量无关账号
    assert (
        compare(short, _profile(handle="sbrfans.bsky.social", display_name="z"), None, NOW).handle
        is None
    )


def test_similar_display_name() -> None:
    facts = compare(PROTECTED, _profile(display_name="Sample Brend"), None, NOW)
    assert facts.display == "similar"
    facts = compare(
        PROTECTED, _profile(display_name="Sample Brand Support Desk"), None, NOW
    )
    assert facts.display == "similar"


def test_unofficial_is_not_a_claim_and_bio_with_protected_name_is() -> None:
    assert not compare(PROTECTED, _profile(bio="Unofficial fan page"), None, NOW).bio_claim
    assert compare(PROTECTED, _profile(bio="Loans from Sample Brand"), None, NOW).bio_claim
    assert compare(PROTECTED, _profile(bio="样本品牌官方客服"), None, NOW).bio_claim


def test_identical_avatar_bytes_count_even_when_hash_is_unusable() -> None:
    flat = Avatar("0000000000000000", "c" * 64)
    protected = Protected(
        "bluesky", "sbrank.bsky.social", "did:plc:o", "Sample Brand", flat
    )
    assert (
        compare(protected, _profile(), Avatar("0000000000000000", "c" * 64), NOW).avatar_distance
        == 0
    )
    assert (
        compare(protected, _profile(), Avatar("0000000000000000", "d" * 64), NOW).avatar_distance
        is None
    )


def test_no_official_avatar_means_no_avatar_signal() -> None:
    protected = Protected(
        "bluesky", "sbrank.bsky.social", "did:plc:o", "Sample Brand", None
    )
    assert compare(protected, _profile(), NEAR, NOW).avatar_distance is None


def test_excluded_accounts() -> None:
    official = ["sbr.int"]
    allowed = ["sbr-fans.bsky.social", "did:plc:friend"]
    assert excluded(PROTECTED, _profile(platform_id="did:plc:official"), allowed, official)
    assert excluded(PROTECTED, _profile(handle="SBR-Fans.bsky.social"), allowed, official)
    assert excluded(PROTECTED, _profile(platform_id="did:plc:friend"), allowed, official)
    assert excluded(PROTECTED, _profile(handle="news.sbr.int"), allowed, official)
    assert excluded(PROTECTED, _profile(handle="sbr.int"), allowed, official)
    assert not excluded(PROTECTED, _profile(handle="sbr.int.evil.com"), allowed, official)
    assert not excluded(PROTECTED, _profile(handle="sbrank.bsky.social.fake"), allowed, official)


def test_profile_json_round_trip_and_rejects_malformed() -> None:
    p = _profile(registered_at=NOW, bio="hi", avatar_url="https://cdn.bsky.app/a.jpg")
    assert Profile.from_json(p.to_json()) == p
    assert Profile.from_json({"platform_id": 1}) is None
    assert Profile.from_json({**p.to_json(), "registered_at": "not a date"}) == _profile(
        bio="hi", avatar_url="https://cdn.bsky.app/a.jpg"
    )
