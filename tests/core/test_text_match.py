import pytest

from opti.core.config import ProjectRules
from opti.core.text_match import TextMatcher


@pytest.fixture(scope="module")
def tm(sbr_rules: ProjectRules) -> TextMatcher:
    return TextMatcher(sbr_rules)


def _terms(tm: TextMatcher, text: str, role: str = "match") -> set[str]:
    return {h.term for h in tm.match(text) if h.role == role}


def test_english_phrase(tm: TextMatcher) -> None:
    hits = tm.match("The Sample Brand approved a loan.")
    assert [h.term for h in hits] == ["Sample Brand"]
    assert "Sample Brand" in hits[0].context


def test_english_phrase_case_insensitive(tm: TextMatcher) -> None:
    assert "Sample Brand" in _terms(tm, "SAMPLE BRAND statement")


def test_traditional_chinese(tm: TextMatcher) -> None:
    terms = _terms(tm, "樣本品牌集團宣布")
    assert {"样本品牌集团", "样本品牌"} <= terms


def test_separated_chinese_and_booster(tm: TextMatcher) -> None:
    text = "样·本·品·牌 低息贷款，先交手续费"
    assert "样本品牌" in _terms(tm, text)
    assert {"低息贷款", "手续费"} <= _terms(tm, text, role="booster")


def test_zero_width(tm: TextMatcher) -> None:
    assert "Sample Brand" in _terms(tm, "Sample ​Brand")


def test_sbr_with_context(tm: TextMatcher) -> None:
    assert "SBR" in _terms(tm, "SBR, the ORBIT lender, said on Monday")


def test_sbr_without_context(tm: TextMatcher) -> None:
    assert "SBR" not in _terms(tm, "SBR reported quarterly results")


def test_sbr_is_case_sensitive(tm: TextMatcher) -> None:
    assert "SBR" not in _terms(tm, "the sbr module in ORBIT docs")


def test_sbr_bank_negative_suppresses(tm: TextMatcher) -> None:
    assert "SBR" not in _terms(tm, "SBR Bank shares rose; analysts compared ORBIT peers")


def test_negative_does_not_suppress_other_hits(tm: TextMatcher) -> None:
    text = "Standard Business Registry of Brazil and the Sample Brand"
    assert _terms(tm, text) == {"Sample Brand"}


def test_sbr_adjacent_to_chinese(tm: TextMatcher) -> None:
    assert "SBR" in _terms(tm, "SBR样本银行合作")


def test_fullwidth_sbr(tm: TextMatcher) -> None:
    assert "SBR" in _terms(tm, "ＳＢＲ 与样本国家")


def test_sbr_glued_to_latin_is_not_a_hit(tm: TextMatcher) -> None:
    assert "SBR" not in _terms(tm, "SBRX ORBIT")


def test_russian_phrase(tm: TextMatcher) -> None:
    assert "Образцовый бренд" in _terms(tm, "Образцовый бренд одобрил кредит")


def test_empty(tm: TextMatcher) -> None:
    assert tm.match("") == []


def test_chinese_hits_have_context(tm: TextMatcher) -> None:
    hits = tm.match("据报道，样本品牌集团今天在春田宣布发行绿色债券。")
    assert hits and all(h.context for h in hits)
    assert any("春田" in h.context for h in hits)


def test_may_match_is_a_relaxed_prefilter(sbr_rules: ProjectRules) -> None:
    matcher = TextMatcher(sbr_rules)
    assert matcher.may_match("Bank approves loan for Sample Brand")
    assert matcher.may_match("SBR board meets")
    assert matcher.may_match("樣本銀行新聞")
    assert not matcher.may_match("Asian Development Bank approves loan")
    assert not matcher.may_match("sbr board meets")
