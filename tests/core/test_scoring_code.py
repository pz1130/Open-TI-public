import pytest

from opti.core import policy
from opti.core.scoring import (
    Category,
    CodeFacts,
    Score,
    Severity,
    alert_threshold,
    code_reasons,
    score_code,
    severity_for,
    with_code_llm,
)


def _facts(**kwargs: object) -> CodeFacts:
    base = dict(hits=1, sensitive_paths=0, internal_terms=False, critical_secrets=0,
                other_secrets=0, secret_in_hit_file=False, newest_secret_age_days=None)  # fmt: skip
    return CodeFacts(**{**base, **kwargs})  # type: ignore[arg-type]


def test_readme_mention_is_info() -> None:
    score = score_code(_facts())
    assert (
        score.category == Category.DATA_LEAK
        and score.value == 15
        and score.severity == Severity.INFO
    )
    assert code_reasons(_facts()) == ["code_mention"]


def test_internal_config_is_medium() -> None:
    score = score_code(_facts(hits=6, sensitive_paths=1, internal_terms=True))
    assert score.breakdown == {"base": 15, "sensitive_path": 20, "internal_terms": 20, "scale": 5}
    assert score.severity == Severity.MEDIUM
    assert code_reasons(_facts(sensitive_paths=1, internal_terms=True)) == [
        "sensitive_path",
        "internal_term",
    ]


def test_critical_secret_in_hit_file_is_critical() -> None:
    facts = _facts(critical_secrets=1, secret_in_hit_file=True, newest_secret_age_days=10)
    score = score_code(facts)
    assert score.category == Category.SECRET_LEAK
    assert score.breakdown == {"base": 45, "secret_kind": 25, "relevance": 20, "recency": 10}
    assert score.severity == Severity.CRITICAL
    assert code_reasons(facts) == ["secret_critical", "secret_in_brand_file"]


def test_old_generic_secret_is_medium() -> None:
    score = score_code(_facts(other_secrets=2, newest_secret_age_days=900))
    assert score.breakdown == {"base": 45, "secret_kind": 10, "relevance": 0, "recency": -10}
    assert score.severity == Severity.MEDIUM
    assert score_code(_facts(other_secrets=1, internal_terms=True)).breakdown["relevance"] == 10


def _secret_score(value: int) -> Score:
    breakdown = {"base": 45, "secret_kind": value - 45}
    return Score(value, severity_for(value), Category.SECRET_LEAK, breakdown)


def test_code_llm_raises_real_secret_in_own_repo() -> None:
    score = with_code_llm(_secret_score(80), "real", "org")
    assert score.value == 100 and score.severity == Severity.CRITICAL
    assert score.breakdown == {"base": 45, "secret_kind": 35, "llm_secret": 10, "llm_relation": 10}
    assert with_code_llm(_secret_score(55), "unsure", "related").value == 60


def test_code_llm_never_drops_below_alert_line() -> None:
    score = with_code_llm(_secret_score(45), "example", "unrelated")
    assert score.value == 40 and score.severity == Severity.MEDIUM
    assert score.breakdown["llm_floor"] == 20 and sum(score.breakdown.values()) == 40
    lowered = with_code_llm(_secret_score(70), "example", "unsure")
    assert lowered.value == 55 and "llm_floor" not in lowered.breakdown


def test_code_llm_replaces_previous_factors() -> None:
    first = with_code_llm(_secret_score(45), "example", "unrelated")
    again = with_code_llm(first, "real", "org")
    assert again.value == 65 and "llm_floor" not in again.breakdown


def test_code_llm_floor_follows_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    configured = policy.OperationsConfig.model_validate(
        {"risk": {"alert_from": "high", "llm_code_example_points": -40}}
    )
    monkeypatch.setattr(policy, "_current", configured)
    assert alert_threshold() == 65
    assert with_code_llm(_secret_score(80), "example", "unsure").value == 65  # 不压到 High 以下
    assert (
        with_code_llm(_secret_score(50), "example", "unsure").value == 50
    )  # 规则本就不告警：不再降
