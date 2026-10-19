from opti.core.scoring import Category, RansomFacts, Severity, score_ransomware


def test_own_organization_is_critical() -> None:
    s = score_ransomware(RansomFacts(party="self", how="domain", age_days=2))
    assert s.category == Category.RANSOMWARE_MENTION
    assert s.breakdown == {"base": 70, "match_strength": 15, "recency": 10}
    assert s.value == 95 and s.severity == Severity.CRITICAL


def test_vendor_tiers_and_age() -> None:
    assert (
        score_ransomware(RansomFacts(party="critical", how="domain", age_days=5)).severity
        == Severity.HIGH
    )
    assert (
        score_ransomware(RansomFacts(party="normal", how="name", age_days=5)).severity
        == Severity.MEDIUM
    )
    old = score_ransomware(RansomFacts(party="normal", how="name", age_days=300))
    assert old.breakdown["recency"] == -15 and old.severity == Severity.LOW
    assert (
        score_ransomware(RansomFacts(party="critical", how="name", age_days=300)).severity
        == Severity.MEDIUM
    )
    assert (
        score_ransomware(RansomFacts(party="high", how="name", age_days=None)).breakdown["recency"]
        == 0
    )
