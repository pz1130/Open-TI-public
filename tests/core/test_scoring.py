import pytest

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatch, DomainMatcher
from opti.core.scoring import (
    Category,
    DomainSignals,
    Severity,
    score_domain,
    score_own_domain_cert,
    severity_for,
    severity_rank,
)


@pytest.fixture(scope="module")
def matcher(sbr_rules: ProjectRules) -> DomainMatcher:
    return DomainMatcher(sbr_rules.domains)


def _m(matcher: DomainMatcher, domain: str) -> DomainMatch:
    m = matcher.match(domain)
    assert m is not None
    return m


def test_worked_example_from_spec(matcher: DomainMatcher) -> None:
    # 设计文档 9.2：新注册 7 天、有登录框、页面含 SBR 名称与 Logo → Critical
    s = score_domain(
        DomainSignals(
            match=_m(matcher, "sbr-loans.com"),
            age_days=7,
            has_login_form=True,
            brand_in_content=True,
            logo_similar=True,
        )
    )
    assert s.category == Category.PHISHING_SITE
    assert s.breakdown == {
        "base": 40,
        "domain_risk": 28,
        "content_risk": 30,
        "intel_hits": 0,
        "benign_signals": 0,
    }
    assert s.value == 98 and s.severity == Severity.CRITICAL


def test_parked_lookalike_is_medium(matcher: DomainMatcher) -> None:
    s = score_domain(DomainSignals(match=_m(matcher, "sbr-loans.com")))
    assert s.category == Category.TYPOSQUAT_DOMAIN
    assert s.value == 43 and s.severity == Severity.MEDIUM


def test_homoglyph_scores_higher_than_plain(matcher: DomainMatcher) -> None:
    s = score_domain(DomainSignals(match=_m(matcher, "xn--br-loans-jhh.com")))
    assert s.value == 47


def test_subdomain_only_is_halved(matcher: DomainMatcher) -> None:
    s = score_domain(DomainSignals(match=_m(matcher, "sbr.example-hosting.com")))
    assert s.value == 29 and s.severity == Severity.LOW


def test_official_embedded_in_subdomain_is_not_halved(matcher: DomainMatcher) -> None:
    # 20（base）+ 25（OFFICIAL_EMBEDDED，不减半）+ 5（.xyz）
    assert score_domain(DomainSignals(match=_m(matcher, "sbr.int.secure-login.xyz"))).value == 50


def test_risky_tld(matcher: DomainMatcher) -> None:
    assert score_domain(DomainSignals(match=_m(matcher, "sbr-portal.top"))).value == 43


def test_popular_domain_is_downgraded(matcher: DomainMatcher) -> None:
    s = score_domain(DomainSignals(match=_m(matcher, "sbr-loans.com"), tranco_rank=5_000))
    assert s.breakdown["benign_signals"] == -30
    assert s.value == 13 and s.severity == Severity.INFO


def test_not_resolving_is_downgraded(matcher: DomainMatcher) -> None:
    s = score_domain(DomainSignals(match=_m(matcher, "sbr-loans.com"), resolves=False))
    assert s.value == 33


def test_mx_and_intel(matcher: DomainMatcher) -> None:
    s = score_domain(DomainSignals(match=_m(matcher, "sbr-loans.com"), has_mx=True, intel_hit=True))
    assert s.value == 88 and s.severity == Severity.CRITICAL
    assert s.category == Category.PHISHING_SITE


def test_value_is_clamped(matcher: DomainMatcher) -> None:
    s = score_domain(
        DomainSignals(
            match=_m(matcher, "sbr.int.secure-login.xyz"),
            age_days=1,
            has_mx=True,
            has_login_form=True,
            brand_in_content=True,
            logo_similar=True,
            intel_hit=True,
        )
    )
    assert s.value == 100


def test_official_cannot_be_scored(matcher: DomainMatcher) -> None:
    with pytest.raises(ValueError, match="status"):
        score_domain(DomainSignals(match=_m(matcher, "sbr.int")))


@pytest.mark.parametrize(
    ("value", "severity"),
    [(100, Severity.CRITICAL), (85, Severity.CRITICAL), (84, Severity.HIGH),
     (65, Severity.HIGH), (64, Severity.MEDIUM), (40, Severity.MEDIUM),
     (39, Severity.LOW), (20, Severity.LOW), (19, Severity.INFO), (0, Severity.INFO)],
)  # fmt: skip
def test_severity_bands(value: int, severity: Severity) -> None:
    assert severity_for(value) == severity


def test_severity_rank() -> None:
    assert severity_rank("info") < severity_rank(Severity.LOW) < severity_rank("medium")
    assert severity_rank(Severity.HIGH) < severity_rank("critical") == 4


@pytest.mark.parametrize(("approved", "expected"), [(False, 70), (True, None), (None, None)])
def test_own_domain_cert(approved: bool | None, expected: int | None) -> None:
    s = score_own_domain_cert(approved)
    if expected is None:
        assert s is None
    else:
        assert s is not None and s.value == expected and s.severity == Severity.HIGH
        assert s.category.value == "unapproved_certificate"


def test_intel_hit_makes_domain_phishing(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    plain = score_domain(DomainSignals(match=m))
    confirmed = score_domain(DomainSignals(match=m, intel_hit=True))
    assert plain.category == Category.TYPOSQUAT_DOMAIN
    assert confirmed.category == Category.PHISHING_SITE
    assert confirmed.breakdown["intel_hits"] == 20 and confirmed.breakdown["base"] == 40
    assert confirmed.value == plain.value + 40


def test_score_url(sbr_rules: ProjectRules) -> None:
    from opti.core.scoring import UrlSignals, score_url
    from opti.core.urls import UrlMatcher

    um = UrlMatcher(sbr_rules)
    path_only = um.match("https://sites.google.com/view/samplebrand-grants")
    assert path_only is not None
    s = score_url(UrlSignals(match=path_only))
    assert s.category == Category.PHISHING_SITE and s.value == 55 and s.severity == Severity.MEDIUM
    assert s.breakdown == {"base": 40, "url_brand": 15, "content_risk": 0, "intel_hits": 0}
    confirmed = score_url(UrlSignals(match=path_only, intel_hit=True, has_login_form=True))
    assert confirmed.value == 90 and confirmed.severity == Severity.CRITICAL
    trick = um.match("https://sbr.int@evil.top/login")
    assert trick is not None and score_url(UrlSignals(match=trick)).breakdown["url_brand"] == 20
    host = um.match("https://sbr-loans.com/x")
    assert host is not None
    with pytest.raises(ValueError):
        score_url(UrlSignals(match=host))


def test_score_signal() -> None:
    from opti.core.scoring import SignalFacts, score_signal

    reported = score_signal(SignalFacts("reported"))
    assert reported.category == Category.REPORTED_PHISHING and reported.value == 60
    assert reported.severity == Severity.MEDIUM
    assert score_signal(SignalFacts("reported", has_login_form=True)).value == 75
    canary = score_signal(SignalFacts("canary", intel_hit=True))
    assert (
        canary.category == Category.CLONE_SITE
        and canary.value == 80
        and canary.breakdown["intel_hits"] == 0
    )
    assert score_signal(SignalFacts("hotlink", volume=150)).value == 40 + 15 + 20
    spoof = score_signal(SignalFacts("dmarc_fail", volume=12))
    assert (
        spoof.category == Category.EMAIL_SPOOFING
        and spoof.value == 65
        and spoof.severity == Severity.HIGH
    )
    with pytest.raises(ValueError):
        score_signal(SignalFacts("rumour"))


def test_with_signal_adds_points(sbr_rules: ProjectRules) -> None:
    from opti.core.scoring import with_signal

    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    base = score_domain(DomainSignals(match=m))
    boosted = with_signal(base, "reported")
    assert boosted.value == base.value + 15 and boosted.breakdown["owned_signal"] == 15
    assert boosted.category == base.category
