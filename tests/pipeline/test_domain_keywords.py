import pytest

from opti.core.config import ProjectRules
from opti.pipeline import domain_keywords as dk
from opti.pipeline.domain_keywords import KeywordInvalid


def _reason(exc: pytest.ExceptionInfo[KeywordInvalid]) -> str:
    return exc.value.reason


def test_add_brand_normalizes_and_appends(sbr_rules: ProjectRules) -> None:
    out = dk.add(sbr_rules, "brand", "  SBR-Fund ")
    assert out.domains.brand_tokens == (*sbr_rules.domains.brand_tokens, "sbr-fund")
    assert sbr_rules.domains.brand_tokens[-1] != "sbr-fund"  # 原规则不变


def test_add_duplicate_returns_same_rules(sbr_rules: ProjectRules) -> None:
    assert dk.add(sbr_rules, "brand", "SBR") == sbr_rules
    assert dk.add(sbr_rules, "official", "www.sbr.int") == sbr_rules
    assert dk.add(sbr_rules, "restricted", "orbit", ["coin"]) == sbr_rules


@pytest.mark.parametrize(
    "value", ["a", "nd b", "sbr.int", "x" * 64, "sbr_", "样本/银行", "样本*", "样本😀"]
)
def test_add_brand_rejects_invalid_tokens(sbr_rules: ProjectRules, value: str) -> None:
    with pytest.raises(KeywordInvalid) as e:
        dk.add(sbr_rules, "brand", value)
    assert _reason(e) == "invalid_token"


@pytest.mark.parametrize("value", ["样本", "品牌", "樣本", "样本-SBR"])
def test_chinese_tokens_can_be_added_viewed_and_removed(
    sbr_rules: ProjectRules, value: str
) -> None:
    token = value.lower()
    rules = dk.add(sbr_rules, "brand", f" {value} ")
    assert dk.normalize("brand", value) == token
    assert rules.domains.brand_tokens[-1] == token
    assert dk.remove(rules, "brand", value) == sbr_rules


def test_chinese_restricted_tokens_and_affixes(sbr_rules: ProjectRules) -> None:
    rules = dk.add(sbr_rules, "restricted", "样本", ["贷款", "fund"])
    assert rules.domains.restricted_tokens["样本"] == ("贷款", "fund")
    rules = dk.set_affixes(rules, "样本", ["银行"])
    assert rules.domains.restricted_tokens["样本"] == ("银行",)
    assert dk.remove(rules, "restricted", "样本") == sbr_rules


def test_brand_and_restricted_conflict(sbr_rules: ProjectRules) -> None:
    with pytest.raises(KeywordInvalid) as e:
        dk.add(sbr_rules, "brand", "orbit")
    assert _reason(e) == "token_conflict"
    with pytest.raises(KeywordInvalid) as e:
        dk.add(sbr_rules, "restricted", "sbr", ["fund"])
    assert _reason(e) == "token_conflict"


def test_add_restricted_requires_valid_affixes(sbr_rules: ProjectRules) -> None:
    out = dk.add(sbr_rules, "restricted", "Silk", ["Road", "road", "pay"])
    assert out.domains.restricted_tokens["silk"] == ("road", "pay")
    for affixes in ([], ["ok", "bad affix"]):
        with pytest.raises(KeywordInvalid) as e:
            dk.add(sbr_rules, "restricted", "silk", affixes)
        assert _reason(e) == "invalid_affix"


def test_set_affixes(sbr_rules: ProjectRules) -> None:
    out = dk.set_affixes(sbr_rules, "ORBIT", ["fund", "coin"])
    assert out.domains.restricted_tokens["orbit"] == ("fund", "coin")
    with pytest.raises(KeywordInvalid) as e:
        dk.set_affixes(sbr_rules, "nope", ["fund"])
    assert _reason(e) == "not_found"
    with pytest.raises(KeywordInvalid) as e:
        dk.set_affixes(sbr_rules, "orbit", [])
    assert _reason(e) == "invalid_affix"


def test_domains_store_registered_domain(sbr_rules: ProjectRules) -> None:
    out = dk.add(sbr_rules, "lookalike", "Login.SBR-Group.com.")
    assert out.domains.known_lookalikes[-1] == "sbr-group.com"
    out = dk.add(sbr_rules, "official", "careers.sbr.org")
    assert out.domains.official[-1] == "sbr.org"
    with pytest.raises(KeywordInvalid) as e:
        dk.add(sbr_rules, "official", "not a domain")
    assert _reason(e) == "invalid_domain"


def test_official_and_lookalike_conflict(sbr_rules: ProjectRules) -> None:
    with pytest.raises(KeywordInvalid) as e:
        dk.add(sbr_rules, "lookalike", "sbr.int")
    assert _reason(e) == "domain_conflict"
    with pytest.raises(KeywordInvalid) as e:
        dk.add(sbr_rules, "official", "sbrbank.com")
    assert _reason(e) == "domain_conflict"


def test_remove(sbr_rules: ProjectRules) -> None:
    out = dk.remove(sbr_rules, "brand", "OrbitBank")
    assert "orbitbank" not in out.domains.brand_tokens
    out = dk.remove(sbr_rules, "restricted", "orbit")
    assert out.domains.restricted_tokens == {}
    out = dk.remove(sbr_rules, "lookalike", "sbrbank.com")
    assert out.domains.known_lookalikes == ()
    with pytest.raises(KeywordInvalid) as e:
        dk.remove(sbr_rules, "brand", "absent")
    assert _reason(e) == "not_found"


def test_cannot_remove_last_brand_or_official(sbr_rules: ProjectRules) -> None:
    with pytest.raises(KeywordInvalid) as e:
        dk.remove(sbr_rules, "official", "sbr.int")
    assert _reason(e) == "last_item"
    rules = sbr_rules
    for token in sbr_rules.domains.brand_tokens[1:]:
        rules = dk.remove(rules, "brand", token)
    with pytest.raises(KeywordInvalid) as e:
        dk.remove(rules, "brand", sbr_rules.domains.brand_tokens[0])
    assert _reason(e) == "last_item"


def test_other_rule_fields_untouched(sbr_rules: ProjectRules) -> None:
    out = dk.add(sbr_rules, "brand", "sbrx")
    assert out.sets == sbr_rules.sets
    assert out.domains.combo_affixes == sbr_rules.domains.combo_affixes
    assert out.project == sbr_rules.project


def test_describe() -> None:
    assert dk.describe("added", "brand", "sbrx") == "监视列表：新增品牌词 sbrx"
    assert dk.describe("updated", "restricted", "orbit") == "监视列表：修改受限品牌词 orbit"
    assert dk.describe("removed", "lookalike", "a.com") == "监视列表：删除合法第三方 a.com"


@pytest.mark.parametrize("kind", ["brand", "restricted"])
def test_hyphen_only_tokens_are_rejected(sbr_rules: ProjectRules, kind: dk.KeywordKind) -> None:
    with pytest.raises(KeywordInvalid, match="invalid_token"):
        dk.add(sbr_rules, kind, "--", ["fund"])
    with pytest.raises(KeywordInvalid, match="invalid_affix"):
        dk.add(sbr_rules, "restricted", "silk", ["---"])


def test_equivalent_matching_tokens_cannot_cross_brand_categories(sbr_rules: ProjectRules) -> None:
    with pytest.raises(KeywordInvalid, match="token_conflict"):
        dk.add(sbr_rules, "brand", "o-r-b-i-t")
    with pytest.raises(KeywordInvalid, match="token_conflict"):
        dk.add(sbr_rules, "restricted", "s-b-r", ["fund"])


def test_hyphen_variants_within_a_category_are_duplicates(sbr_rules: ProjectRules) -> None:
    # 匹配器按去掉连字符的词建索引：同类别里的写法变体会覆盖原项（o-rbit 会把 orbit 的词缀换掉）
    with pytest.raises(KeywordInvalid, match="duplicate_token"):
        dk.add(sbr_rules, "brand", "s-br")
    with pytest.raises(KeywordInvalid, match="duplicate_token"):
        dk.add(sbr_rules, "restricted", "o-rbit", ["fund"])
    assert dk.add(sbr_rules, "brand", "sbr") == sbr_rules  # 完全相同仍视为没有变化
