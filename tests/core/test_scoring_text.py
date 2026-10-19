from opti.core.scoring import Category, Severity, TextFacts, score_text, text_reasons


def _facts(**changes: object) -> TextFacts:
    values = dict(kind="mention", strong=True, boosters=0, age_days=1, reprints=1)
    values.update(changes)
    return TextFacts(**values)  # type: ignore[arg-type]


def test_mentions_are_informational() -> None:
    assert score_text(_facts()).value == 25
    weak = score_text(_facts(strong=False))
    assert weak.category == Category.BRAND_MENTION and weak.severity == Severity.INFO
    assert text_reasons(_facts(strong=False)) == ["brand_abbreviation"]


def test_fraud_score_and_cap() -> None:
    result = score_text(_facts(kind="fraud", boosters=2))
    assert result.category == Category.FRAUD_SCAM and result.severity == Severity.HIGH
    assert result.breakdown == {
        "base": 45,
        "match_strength": 15,
        "boosters": 20,
        "recency": 0,
        "spread": 0,
    }
    assert score_text(_facts(kind="fraud", boosters=9)).breakdown["boosters"] == 30
    assert text_reasons(_facts(kind="fraud", boosters=2)) == ["brand_name", "fraud_terms"]


def test_press_age_and_spread() -> None:
    result = score_text(_facts(kind="press", boosters=5, age_days=30, reprints=6))
    assert result.category == Category.NEGATIVE_PRESS and result.severity == Severity.HIGH
    assert result.breakdown == {
        "base": 35,
        "match_strength": 15,
        "boosters": 20,
        "recency": -10,
        "spread": 5,
    }
    assert text_reasons(_facts(kind="press", boosters=1, age_days=30, reprints=6)) == [
        "brand_name",
        "press_terms",
        "old_article",
        "widely_reprinted",
    ]
