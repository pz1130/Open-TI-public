from opti.core.normalize import compact_text, fold, normalize_text, to_simplified


def test_fullwidth_is_folded() -> None:
    assert normalize_text("ＳＢＲ　Ｂａｎｋ") == "sbr bank"


def test_zero_width_removed() -> None:
    assert normalize_text("Sample ​Brand‍") == "sample brand"


def test_traditional_to_simplified() -> None:
    assert to_simplified("樣本品牌集團") == "样本品牌集团"
    assert normalize_text("樣本品牌集團") == "样本品牌集团"


def test_case_preserved_when_requested() -> None:
    assert normalize_text("  SBR\t and   ORBIT ", casefold=False) == "SBR and ORBIT"


def test_compact_strips_separators() -> None:
    assert compact_text("样·本·品·牌") == "样本品牌"
    assert compact_text("样 本 品 牌") == "样本品牌"
    assert compact_text("Sample-Brand") == "samplebrand"


def test_fold_keeps_length() -> None:
    s = "İstanbul SBR"
    assert len(fold(s)) == len(s)
    assert fold("SBR Bank") == "sbr bank"


def test_empty() -> None:
    assert normalize_text("") == ""
    assert compact_text("") == ""
