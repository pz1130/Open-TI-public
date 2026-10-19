from opti.core.scoring import Category, ExposureFacts, Severity, exposure_reasons, score_exposure


def test_recent_password_breach_is_high() -> None:
    f = ExposureFacts(
        kind="breach",
        affected=12,
        data_classes=frozenset({"Email addresses", "Passwords"}),
        age_days=120,
    )
    s = score_exposure(f)
    assert s.category == Category.CREDENTIAL_EXPOSURE
    assert s.breakdown == {
        "base": 30,
        "credential_risk": 25,
        "recency": 15,
        "scale": 10,
        "source_quality": 0,
    }
    assert s.value == 80 and s.severity == Severity.HIGH
    assert exposure_reasons(f) == ["passwords_exposed", "recent_breach", "many_accounts"]


def test_infostealer_is_critical_when_recent() -> None:
    s = score_exposure(ExposureFacts(kind="stealer", affected=1, age_days=30))
    assert s.value == 90 and s.severity == Severity.CRITICAL
    assert exposure_reasons(ExposureFacts(kind="stealer", affected=1, age_days=30)) == [
        "infostealer",
        "recent_breach",
    ]


def test_old_and_low_quality_breaches_score_low() -> None:
    old = score_exposure(
        ExposureFacts(
            kind="breach", affected=40, data_classes=frozenset({"Passwords"}), age_days=12 * 365
        )
    )
    assert (
        old.breakdown["recency"] == -10 and old.severity == Severity.MEDIUM
    )  # 只进日报，不立即推送
    emails_only = score_exposure(
        ExposureFacts(
            kind="breach", affected=3, data_classes=frozenset({"Email addresses"}), age_days=2000
        )
    )
    assert emails_only.severity == Severity.LOW
    fake = score_exposure(
        ExposureFacts(
            kind="breach",
            affected=50,
            data_classes=frozenset({"Passwords"}),
            age_days=10,
            fabricated=True,
        )
    )
    assert fake.breakdown["source_quality"] == -40 and fake.severity == Severity.MEDIUM
    spam = score_exposure(
        ExposureFacts(
            kind="breach",
            affected=50,
            data_classes=frozenset({"Email addresses"}),
            age_days=10,
            spam_list=True,
            verified=False,
        )
    )
    assert spam.breakdown["source_quality"] == -20
    assert exposure_reasons(ExposureFacts(kind="breach", affected=0)) == ["credential_exposure"]


def test_secret_like_classes_and_unknown_age() -> None:
    s = score_exposure(
        ExposureFacts(kind="breach", affected=0, data_classes=frozenset({"Password hints"}))
    )
    assert (
        s.breakdown["credential_risk"] == 10
        and s.breakdown["recency"] == 0
        and s.breakdown["scale"] == 0
    )
