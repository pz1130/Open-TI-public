from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.core.report import domain_report


def test_domain_report(sbr_rules: ProjectRules) -> None:
    m = DomainMatcher(sbr_rules.domains)
    hit = domain_report(m, "SBR-Loans.com")
    assert hit["domain"] == "sbr-loans.com" and hit["status"] == "match"
    assert hit["score"]["severity"] in {"low", "medium", "high", "critical", "info"}
    assert set(hit["score"]["breakdown"]) >= {"base"}
    assert domain_report(m, "sbrbank.com")["status"] == "known_lookalike"
    assert "score" not in domain_report(m, "sbr.int")
    assert domain_report(m, "example.org") == {"input": "example.org", "status": "no_match"}
