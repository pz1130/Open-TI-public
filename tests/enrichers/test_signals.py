from datetime import UTC, datetime

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.core.scoring import score_domain
from opti.enrichers.signals import build_domain_signals

NOW = datetime(2026, 10, 2, tzinfo=UTC)


def test_signals_from_enrichment(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    sig = build_domain_signals(
        m,
        {
            "dns": {"exists": True, "mx": ["10 mx.evil.example"]},
            "rdap": {"registration": "2026-09-25T10:00:00Z"},
            "tranco": {"rank": None, "available": True},
        },
        now=NOW,
    )
    assert sig.age_days == 6 and sig.resolves is True and sig.has_mx is True
    assert sig.tranco_rank is None
    assert score_domain(sig).value == 53  # 43 + 新注册 5 + MX 5


def test_signals_tolerate_missing_and_bad_values(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    sig = build_domain_signals(
        m,
        {"dns": {"exists": None, "error": "Timeout"}, "rdap": {"registration": "garbage"}},
        now=NOW,
    )
    assert sig.age_days is None and sig.resolves is None and sig.has_mx is None


def test_naive_registration_date_is_treated_as_utc(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    sig = build_domain_signals(m, {"rdap": {"registration": "2026-09-01T00:00:00"}}, now=NOW)
    assert sig.age_days == 31


def test_http_probe_signals_make_phishing(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    sig = build_domain_signals(
        m,
        {
            "dns": {"exists": True, "mx": []},
            "rdap": {"registration": "2026-09-25T10:00:00Z"},
            "http_probe": {
                "reachable": True,
                "status": 200,
                "has_password_field": True,
                "brand_terms": ["Sample Brand"],
            },
        },
        now=NOW,
    )
    assert sig.has_login_form is True and sig.brand_in_content is True
    s = score_domain(sig)
    assert s.category.value == "phishing_site" and s.value == 93


def test_unreachable_site_gives_unknown_content(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert m is not None
    sig = build_domain_signals(m, {"http_probe": {"reachable": False, "error": "x"}}, now=NOW)
    assert sig.has_login_form is None and sig.brand_in_content is None


def test_url_signals_and_intel(sbr_rules: ProjectRules) -> None:
    from opti.core.urls import UrlMatcher
    from opti.enrichers.signals import build_url_signals

    m = UrlMatcher(sbr_rules).match("https://sites.google.com/view/sbr-loans")
    assert m is not None
    probe = {
        "http_probe": {
            "reachable": True,
            "status": 200,
            "has_password_field": True,
            "brand_terms": ["SBR"],
        }
    }
    sig = build_url_signals(m, probe, intel_hit=True)
    assert sig.has_login_form is True and sig.brand_in_content is True and sig.intel_hit is True
    assert build_url_signals(m, {}, intel_hit=None).has_login_form is None
    dm = DomainMatcher(sbr_rules.domains).match("sbr-loans.com")
    assert dm is not None
    assert build_domain_signals(dm, {}, intel_hit=True).intel_hit is True
