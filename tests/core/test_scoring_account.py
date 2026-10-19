import pytest

from opti.core.scoring import AccountFacts, Category, Severity, score_account


@pytest.mark.parametrize(
    ("facts", "value", "severity"),
    [
        # 仅名称相似：最多 35 分，低危，不开告警
        (AccountFacts(display="same", handle="same"), 35, Severity.LOW),
        (AccountFacts(display="similar", handle="contains"), 18, Severity.INFO),
        # 名称 + 自称官方 + 新注册：中危
        (
            AccountFacts(display="same", handle="same", bio_claim=True, age_days=5),
            55,
            Severity.MEDIUM,
        ),
        # 名称 + 头像：高危
        (AccountFacts(display="same", handle="same", avatar_distance=3), 75, Severity.HIGH),
        # 全部命中：严重
        (
            AccountFacts(
                display="same", handle="same", avatar_distance=0, bio_claim=True, age_days=0
            ),
            95,
            Severity.CRITICAL,
        ),
    ],
)
def test_signals_add_up_to_severity(facts: AccountFacts, value: int, severity: Severity) -> None:
    score = score_account(facts)
    assert (score.value, score.severity, score.category) == (
        value,
        severity,
        Category.IMPERSONATION_ACCOUNT,
    )


def test_breakdown_names_each_signal() -> None:
    score = score_account(
        AccountFacts(display="similar", handle="contains", avatar_distance=8, age_days=30)
    )
    assert score.breakdown == {
        "display_similar": 10,
        "handle_contains": 8,
        "avatar": 40,
        "new_account": 10,
    }


def test_avatar_beyond_threshold_and_old_accounts_score_nothing() -> None:
    score = score_account(AccountFacts(display="same", avatar_distance=9, age_days=31))
    assert score.breakdown == {"display_same": 20}
