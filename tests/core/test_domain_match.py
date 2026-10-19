import pytest

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher, Reason


@pytest.fixture(scope="module")
def matcher(sbr_rules: ProjectRules) -> DomainMatcher:
    return DomainMatcher(sbr_rules.domains)


@pytest.mark.parametrize(
    ("domain", "reason"),
    [
        ("sbr-loans.com", Reason.BRAND_LABEL),
        ("sbr-loans.com", Reason.FRAUD_AFFIX),
        ("sbrloans.com", Reason.BRAND_COMBO),
        ("login-sbr.net", Reason.BRAND_LABEL),
        ("loginsbr.net", Reason.BRAND_COMBO),
        ("sbr2026.top", Reason.BRAND_COMBO),
        ("sbr.int.secure-login.xyz", Reason.OFFICIAL_EMBEDDED),
        ("sbr-int.com", Reason.OFFICIAL_EMBEDDED),
        ("sbrint.org", Reason.OFFICIAL_EMBEDDED),
        ("samplebrand.org", Reason.BRAND_LABEL),
        ("samplebrand-careers.org", Reason.BRAND_SUBSTRING),
        ("orbitbamk.com", Reason.BRAND_FUZZY),
        ("xn--br-loans-jhh.com", Reason.HOMOGLYPH),
        ("xn--br-loans-jhh.com", Reason.BRAND_LABEL),
    ],
)
def test_lookalikes_match(matcher: DomainMatcher, domain: str, reason: Reason) -> None:
    m = matcher.match(domain)
    assert m is not None and m.status == "match", domain
    assert m.has(reason), (domain, m.reasons)


@pytest.mark.parametrize(
    "domain",
    ["crossbrace.com", "busbridge-power.net", "glassbreaker.shop", "jobsbrokerbank.com", "example.org",
     "sbrox.io", "", "localhost", "1.2.3.4", "a b.com"],
)  # fmt: skip
def test_unrelated_or_invalid_is_none(matcher: DomainMatcher, domain: str) -> None:
    assert matcher.match(domain) is None


@pytest.mark.parametrize("domain", ["sbr.int", "mail.sbr.int", "*.SBR.INT."])
def test_official(matcher: DomainMatcher, domain: str) -> None:
    m = matcher.match(domain)
    assert m is not None and m.status == "official" and m.reasons == ()


@pytest.mark.parametrize("domain", ["sbrbank.com", "www.sbrbank.com"])
def test_known_lookalike(matcher: DomainMatcher, domain: str) -> None:
    m = matcher.match(domain)
    assert m is not None and m.status == "known_lookalike"


def test_subdomain_only(matcher: DomainMatcher) -> None:
    m = matcher.match("sbr.example-hosting.com")
    assert m is not None and m.subdomain_only


def test_official_embedded_is_not_subdomain_only(matcher: DomainMatcher) -> None:
    m = matcher.match("sbr.int.secure-login.xyz")
    assert m is not None and not m.subdomain_only


def test_registered_on_free_hosting_is_not_subdomain_only(matcher: DomainMatcher) -> None:
    m = matcher.match("sbr-loans.github.io")
    assert m is not None and not m.subdomain_only
    assert any(r.where == "registered" for r in m.reasons)


def test_undecodable_punycode_label_does_not_crash(matcher: DomainMatcher) -> None:
    m = matcher.match("xn--zz.sbr-loans.com")
    assert m is not None and m.has(Reason.BRAND_LABEL)


def test_long_and_deep_names(matcher: DomainMatcher) -> None:
    long_label = "sbr-" + "x" * 59
    m = matcher.match(f"{long_label}.com")
    assert m is not None and m.has(Reason.BRAND_LABEL)
    deep = ".".join(["a"] * 10) + ".sbr-loans.com"
    m = matcher.match(deep)
    assert m is not None and m.registered == "sbr-loans.com"


def test_reasons_are_deduplicated(matcher: DomainMatcher) -> None:
    m = matcher.match("sbr-loans.com")
    assert m is not None
    assert len(m.reasons) == len(set(m.reasons))


def test_exact_fraud_affix_on_segment_and_combo(matcher: DomainMatcher) -> None:
    # 连字符整段，或组合匹配记下的剩余段，恰好是 loans
    for domain in ("sbr-loans.com", "sbrloans.com"):
        m = matcher.match(domain)
        assert m is not None and m.has(Reason.FRAUD_AFFIX), domain


def test_paypal_is_brand_label_without_fraud_affix(matcher: DomainMatcher) -> None:
    m = matcher.match("sbr-paypal.com")
    assert m is not None and m.has(Reason.BRAND_LABEL)
    assert not m.has(Reason.FRAUD_AFFIX)


@pytest.mark.parametrize(
    "domain",
    [
        "sbr-investigation.com",
        "sbr-accounting.com",
        "sbr-migrant.com",
        "sbr-payroll.com",
        "samplebrandinvestigation.org",
        "samplebrandaccounting.org",
        "samplebrandmigrant.org",
        "samplebrandpayroll.org",
        "samplebrand-investigation.org",
        "samplebrand-payroll.org",
        "samplebrandloans.org",
        "orbitbamkpayroll.com",
    ],
)
def test_fraud_word_inside_longer_segment_or_leftover_is_not_affix(
    matcher: DomainMatcher, domain: str
) -> None:
    m = matcher.match(domain)
    assert m is not None, domain
    assert not m.has(Reason.FRAUD_AFFIX), (domain, m.reasons)


def test_exact_affix_segment_beside_fuzzy_brand_still_counts(matcher: DomainMatcher) -> None:
    m = matcher.match("orbitbamk-pay.com")
    assert m is not None and m.has(Reason.BRAND_FUZZY) and m.has(Reason.FRAUD_AFFIX)


@pytest.mark.parametrize(
    "domain",
    ["orbitfund.org", "orbit-fund.org", "fundorbit.com", "orbit-invest.com", "orbitcoin.io",
     "secure.orbit-finance.top"],
)  # fmt: skip
def test_restricted_token_matches_only_with_its_affixes(
    matcher: DomainMatcher, domain: str
) -> None:
    m = matcher.match(domain)
    assert m is not None and m.status == "match", domain
    assert any(r.reason == Reason.BRAND_COMBO and r.token == "orbit" for r in m.reasons), m.reasons


@pytest.mark.parametrize(
    "domain",
    ["orbit.com", "orbit-music.com", "orbitschool.net", "orbit-center.pro", "exorbitant.com",
     "abaexorbitanthub.com", "orbitloginx.com"],
)  # fmt: skip
def test_restricted_token_without_affix_is_ignored(matcher: DomainMatcher, domain: str) -> None:
    assert matcher.match(domain) is None, domain


def test_restricted_token_counts_fraud_affix(matcher: DomainMatcher) -> None:
    m = matcher.match("orbit-loan.com")
    assert m is not None and m.has(Reason.FRAUD_AFFIX)


def test_hyphenated_restricted_affix_matches_compound_domain(sbr_rules: ProjectRules) -> None:
    rules = sbr_rules.domains.model_copy(update={"restricted_tokens": {"silk-road": ("lo-an",)}})
    found = DomainMatcher(rules).match("silkroadloan.top")
    assert found is not None and found.has(Reason.BRAND_COMBO)
    assert any(r.token == "silkroad" for r in found.reasons)
