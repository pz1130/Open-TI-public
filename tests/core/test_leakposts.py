from datetime import UTC, datetime

import pytest

from opti.core.leakposts import LeakPostError, leak_post_payload, parse_post, parse_time, post_key

HOSTS = ("www.ransomware.live", "ransomware.live")


def test_parse_time() -> None:
    assert parse_time("2026-10-01 12:34:56.123456") == datetime(
        2026, 10, 1, 12, 34, 56, 123456, tzinfo=UTC
    )
    assert parse_time("2026-10-01T12:00:00Z") == datetime(2026, 10, 1, 12, tzinfo=UTC)
    assert parse_time("2026-10-01") == datetime(2026, 10, 1, tzinfo=UTC)
    assert parse_time("yesterday") is None and parse_time(None) is None


def test_field_aliases() -> None:
    v1 = leak_post_payload(
        {"post_title": "Acme Inc", "group_name": "LockBit3", "discovered": "2026-10-01 10:00:00",
         "website": "www.acme.example", "post_url": "https://www.ransomware.live/id/abc"},
        source="ransomware_live", allow_hosts=HOSTS,
    )  # fmt: skip
    v2 = leak_post_payload(
        {"victim": "Acme Inc", "group": "lockbit3", "discovered": "2026-10-01T10:00:00Z", "domain": "acme.example",
         "activity": "Technology", "country": "US", "url": "https://www.ransomware.live/id/abc"},
        source="ransomware_live", allow_hosts=HOSTS,
    )  # fmt: skip
    assert v1 is not None and v2 is not None
    p1, p2 = parse_post(v1), parse_post(v2)
    assert p1.key == p2.key == post_key("lockbit3", "Acme Inc") == "lockbit3:acme"
    assert p2.activity == "Technology" and p2.country == "US"
    assert p1.links == ("https://www.ransomware.live/id/abc",)
    assert leak_post_payload({"victim": "x"}, source="s", allow_hosts=HOSTS) is None  # 缺团伙与日期


def test_post_key_keeps_distinct_unicode_groups_and_long_victims() -> None:
    assert post_key("团伙甲", "Acme Inc") != post_key("团伙乙", "Acme Inc")
    shared = "A" * 290
    assert post_key("akira", shared + " One") != post_key("akira", shared + " Two")
    assert len(post_key("akira", shared + " One")) <= 300


def test_links_and_description_are_sanitized() -> None:
    payload = leak_post_payload(
        {"victim": "Acme", "group": "akira", "discovered": "2026-10-01",
         "description": "line1\x00\x1b[31m\nline2   " + "x" * 2000,
         "url": ["http://www.ransomware.live/a", "javascript:alert(1)", "http://lockbitxyz.onion/post/1",
                 "https://evil.example/a", "https://ransomware.live/b"]},
        source="ransomware_live", allow_hosts=HOSTS,
    )  # fmt: skip
    assert payload is not None
    post = parse_post(payload)
    assert post.links == ("https://ransomware.live/b",)
    assert "hxxp://lockbitxyz[.]onion/post/1" in post.other_links
    assert "javascript[:]alert(1)" in post.other_links
    assert all(
        not o.lower().startswith(("http:", "https:", "javascript:")) for o in post.other_links
    )
    assert "\x00" not in post.description and "\x1b" not in post.description
    assert post.description.startswith("line1 [31m line2") and len(post.description) == 1000


def test_parse_post_rejects() -> None:
    good = leak_post_payload(
        {"victim": "Acme", "group": "akira", "discovered": "2026-10-01"},
        source="s",
        allow_hosts=HOSTS,
    )
    assert good is not None
    for bad in ({"leak_post": {**good["leak_post"], "victim": ""}}, {"leak_post": {**good["leak_post"], "discovered": "?"}},
                {"leak_post": "nope"}, {}):  # fmt: skip
        with pytest.raises(LeakPostError):
            parse_post(bad)


def test_parse_post_revalidates_links() -> None:
    payload = leak_post_payload(
        {"victim": "Acme", "group": "akira", "discovered": "2026-10-01"},
        source="ransomware_live",
        allow_hosts=HOSTS,
    )
    assert payload is not None
    payload["leak_post"]["links"] = [
        "javascript:alert(1)",
        "https://ransomware.live.evil.example/post",
        "https://ransomware.live/post",
    ]
    payload["leak_post"]["other_links"] = ["https://evil.example/post", "javascript:alert(2)"]
    post = parse_post(payload)
    assert post.links == ("https://ransomware.live/post",)
    assert all(not u.startswith(("https:", "javascript:")) for u in post.other_links)
