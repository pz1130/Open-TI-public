import pytest

from opti.core.config import ProjectRules
from opti.core.urls import UrlMatcher, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "HTTPS://SBR-Loans.COM:443/Login?utm_source=x&id=7#top",
            "https://sbr-loans.com/Login?id=7",
        ),
        ("http://sbr-loans.com:80", "http://sbr-loans.com/"),
        ("http://sbr-loans.com:8080/a", "http://sbr-loans.com:8080/a"),
        ("sbr-loans.com/apply", "http://sbr-loans.com/apply"),
        ("https://user:pw@evil.top/x", "https://evil.top/x"),
        ("https://xn--br-loans-jhh.com/", "https://ѕbr-loans.com/"),
        ("http://203.0.113.5/sbr/login", "http://203.0.113.5/sbr/login"),
        ("ftp://sbr-loans.com/", None),
        ("javascript:alert(1)", None),
        ("https://", None),
        ("https://sbr-loans.com:99999/", None),
        ("https://sbr-loans.com/" + "a" * 3000, None),
    ],
)
def test_normalize_url(raw: str, expected: str | None) -> None:
    assert normalize_url(raw) == expected


def test_host_match_is_domain_kind(sbr_rules: ProjectRules) -> None:
    m = UrlMatcher(sbr_rules).match("https://sbr-loans.com/login")
    assert m is not None and m.kind == "domain" and m.host == "sbr-loans.com"
    d = m.to_dict()
    assert d["kind"] == "domain" and d["host_status"] == "match"
    assert {r["reason"] for r in d["reasons"]} >= {"brand_label"}


def test_path_only_is_url_kind(sbr_rules: ProjectRules) -> None:
    m = UrlMatcher(sbr_rules).match("https://sites.google.com/view/samplebrand-grants")
    assert m is not None and m.kind == "url" and m.host_match is None
    assert m.registered == "google.com"
    assert [(r.token, r.where) for r in m.path_reasons] == [("samplebrand", "path")]


def test_short_token_needs_whole_segment(sbr_rules: ProjectRules) -> None:
    um = UrlMatcher(sbr_rules)
    assert um.match("https://evil.top/SBR/Login").kind == "url"  # type: ignore[union-attr]
    assert um.match("https://evil.top/loan%2Dsbr/").kind == "url"  # type: ignore[union-attr]
    assert um.match("https://evil.top/sbrloans").kind == "url"  # type: ignore[union-attr]
    for raw in (
        "https://evil.top/crossbrace/login",
        "https://evil.top/x?q=sbrox",
        "https://evil.top/sbr2026",
    ):
        m = um.match(raw)
        assert m is not None and m.kind is None, raw


def test_tracking_params_do_not_match(sbr_rules: ProjectRules) -> None:
    m = UrlMatcher(sbr_rules).match("https://evil.top/?utm_campaign=sbr")
    assert m is not None and m.kind is None


def test_restricted_token_not_matched_in_path(sbr_rules: ProjectRules) -> None:
    um = UrlMatcher(sbr_rules)
    assert um.match("https://evil.top/orbit-summit").kind is None  # type: ignore[union-attr]
    assert um.match("https://evil.top/orbitbank-invest").kind == "url"  # type: ignore[union-attr]


def test_userinfo_trick(sbr_rules: ProjectRules) -> None:
    m = UrlMatcher(sbr_rules).match("https://sbr.int@evil.top/login")
    assert m is not None and m.host == "evil.top" and m.url == "https://evil.top/login"
    assert m.kind == "url" and m.path_reasons[0].where == "userinfo"


def test_official_and_known_lookalike_are_ignored(sbr_rules: ProjectRules) -> None:
    um = UrlMatcher(sbr_rules)
    assert um.match("https://sbr.int/careers/sbr").kind is None  # type: ignore[union-attr]
    assert um.match("https://www.sbrbank.com/sbr-loans").kind is None  # type: ignore[union-attr]


def test_could_match_never_misses(sbr_rules: ProjectRules) -> None:
    um = UrlMatcher(sbr_rules)
    samples = [
        "https://sbr-loans.com/x", "https://sites.google.com/view/samplebrand-grants",
        "https://evil.top/SBR/Login", "https://sbr.int@evil.top/login", "https://xn--br-loans-jhh.com/",
        "https://evil.top/sample-brand/apply", "https://example.org/", "https://evil.top/crossbrace",
    ]  # fmt: skip
    for raw in samples:
        m = um.match(raw)
        if m is not None and m.kind is not None:
            assert um.could_match(raw), raw
    assert not um.could_match("https://example.org/news")


@pytest.mark.parametrize(
    "raw",
    [
        "mailto:sbr@evil.top",
        "data:sbr@evil.top",
        "https://evil.top/sbr\n",
        "https://sbr.int\\@evil.top/sbr",
    ],
)
def test_reject_ambiguous_urls(raw: str) -> None:
    assert normalize_url(raw) is None


def test_non_tracking_query_bytes_preserved() -> None:
    assert normalize_url("https://evil.top/sbr?a=%2f&flag&utm_source=x&b=hello%20world") == (
        "https://evil.top/sbr?a=%2f&flag&b=hello%20world"
    )


def test_ipv6_and_encoded_path(sbr_rules: ProjectRules) -> None:
    m = UrlMatcher(sbr_rules).match("http://[2001:db8::1]:8080/%73%62%72/login")
    assert m is not None and m.kind == "url" and m.host == "2001:db8::1"
    assert m.url == "http://[2001:db8::1]:8080/%73%62%72/login"
