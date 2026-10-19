from pathlib import Path
from typing import Any

import pytest
import yaml

from opti.core.config import (
    ConfigError,
    DomainRules,
    ProjectRules,
    Term,
    load_project_rules,
    parse_project_rules,
)
from opti.core.domain_match import DomainMatcher


def _minimal() -> dict[str, Any]:
    return {
        "project": "t",
        "authorization_ref": "AUTH-1",
        "sets": {"brand": {"terms": ["Sample Brand"]}},
        "domains": {"official": ["sbr.int"], "brand_tokens": ["sbr"]},
    }


def _write(tmp_path: Path, data: dict[str, Any]) -> Path:
    p = tmp_path / "keywords.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return p


def test_repo_config_loads(sbr_rules: ProjectRules) -> None:
    assert sbr_rules.project == "sample-brand-protection"
    assert "sbr.int" in sbr_rules.domains.official
    assert "sbrbank.com" in sbr_rules.domains.known_lookalikes
    assert sbr_rules.sets["negative"].role == "negative"
    sbr = next(t for t in sbr_rules.sets["brand"].terms if t.value == "SBR")
    assert sbr.mode == "token" and sbr.case_sensitive and sbr.require_any_within is not None


def test_sbr_bank_is_not_a_brand_term(sbr_rules: ProjectRules) -> None:
    brand_values = {t.value for t in sbr_rules.sets["brand"].terms}
    assert "SBR Bank" not in brand_values
    assert "SBR Bank" in {t.value for t in sbr_rules.sets["negative"].terms}


def test_plain_string_terms_become_term_objects(sbr_rules: ProjectRules) -> None:
    boosters = sbr_rules.sets["fraud_boosters"]
    assert boosters.role == "booster"
    assert all(isinstance(t, Term) for t in boosters.terms)
    assert "手续费" in {t.value for t in boosters.terms}


def test_sets_with_role(sbr_rules: ProjectRules) -> None:
    names = [name for name, _ in sbr_rules.sets_with_role("match")]
    assert names == ["brand"]


def test_missing_authorization_ref(tmp_path: Path) -> None:
    data = _minimal()
    del data["authorization_ref"]
    with pytest.raises(ConfigError, match="authorization_ref"):
        load_project_rules(_write(tmp_path, data))


def test_blank_authorization_ref(tmp_path: Path) -> None:
    data = _minimal()
    data["authorization_ref"] = "   "
    with pytest.raises(ConfigError, match="authorization_ref"):
        load_project_rules(_write(tmp_path, data))


def test_executive_set_requires_approval_ref(tmp_path: Path) -> None:
    data = _minimal()
    data["sets"]["executives"] = {"type": "executive", "terms": ["Some Name"]}
    with pytest.raises(ConfigError, match="approval_ref"):
        load_project_rules(_write(tmp_path, data))


def test_executive_set_with_approval_ref_loads(tmp_path: Path) -> None:
    data = _minimal()
    data["sets"]["executives"] = {
        "type": "executive",
        "approval_ref": "DPO-2026-014",
        "terms": ["Some Name"],
    }
    assert load_project_rules(_write(tmp_path, data)).sets["executives"].type == "executive"


def test_set_named_executives_must_declare_executive_type(tmp_path: Path) -> None:
    # 只写 approval_ref 而漏掉 type 时，集合会被当作普通品牌词：绕过审批校验，
    # 且在 S1-B 中会被下发到外部数据源（设计文档 2.1、2.5）
    data = _minimal()
    data["sets"]["executives"] = {"approval_ref": "DPO-2026-014", "terms": ["Some Name"]}
    with pytest.raises(ConfigError, match="executives") as exc:
        load_project_rules(_write(tmp_path, data))
    assert "type" in str(exc.value)


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    data = _minimal()
    data["domains"]["brand_token"] = ["typo"]
    with pytest.raises(ConfigError, match="brand_token"):
        load_project_rules(_write(tmp_path, data))


def test_domains_are_normalized(tmp_path: Path) -> None:
    data = _minimal()
    data["domains"]["official"] = ["SBR.INT."]
    assert load_project_rules(_write(tmp_path, data)).domains.official == ("sbr.int",)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="找不到"):
        load_project_rules(tmp_path / "nope.yaml")


def test_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("project: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="YAML"):
        load_project_rules(p)


@pytest.mark.parametrize(
    "field",
    ["official", "known_lookalikes", "brand_tokens", "combo_affixes", "fraud_affixes"],
)
@pytest.mark.parametrize("blank", ["", "   ", ".", " . "])
def test_blank_domain_item_is_rejected(tmp_path: Path, field: str, blank: str) -> None:
    data = _minimal()
    data["domains"][field] = [blank]
    with pytest.raises(ConfigError, match=field) as exc:
        load_project_rules(_write(tmp_path, data))
    assert f"{field} 在规范化后为空" in str(exc.value)


def test_hyphen_only_brand_token_is_not_an_empty_config_item(tmp_path: Path) -> None:
    # 规范化只做 strip/lower/rstrip(".")；纯连字符留给匹配器忽略
    data = _minimal()
    data["domains"]["brand_tokens"] = ["-"]
    assert load_project_rules(_write(tmp_path, data)).domains.brand_tokens == ("-",)


def test_matcher_ignores_brand_token_empty_after_hyphen_removal() -> None:
    rules = DomainRules.model_construct(
        official=("sbr.int",),
        known_lookalikes=(),
        brand_tokens=("-",),
        combo_affixes=("login",),
        fraud_affixes=("pay",),
        short_token_max_len=4,
    )
    assert DomainMatcher(rules).match("login.com") is None


@pytest.mark.parametrize("role", [None, "match", "booster"])
def test_set_named_negative_must_declare_negative_role(tmp_path: Path, role: str | None) -> None:
    data = _minimal()
    body: dict[str, Any] = {"terms": ["SBR Bank"]}
    if role is not None:
        body["role"] = role
    data["sets"]["negative"] = body
    with pytest.raises(ConfigError, match="negative") as exc:
        load_project_rules(_write(tmp_path, data))
    assert "role" in str(exc.value)


def test_restricted_tokens_are_normalized(tmp_path: Path) -> None:
    data = _minimal()
    data["domains"]["restricted_tokens"] = {" ORBIT ": [" Fund ", "BANK"]}
    rules = load_project_rules(_write(tmp_path, data))
    assert rules.domains.restricted_tokens == {"orbit": ("fund", "bank")}


@pytest.mark.parametrize("value", [{"orbit": []}, {"": ["fund"]}, {"orbit": [" "]}])
def test_restricted_tokens_reject_empty(tmp_path: Path, value: dict[str, list[str]]) -> None:
    data = _minimal()
    data["domains"]["restricted_tokens"] = value
    with pytest.raises(ConfigError, match="restricted_tokens"):
        load_project_rules(_write(tmp_path, data))


def test_parse_from_text_and_reject_aliases() -> None:
    text = yaml.safe_dump(_minimal(), allow_unicode=True)
    assert parse_project_rules(text, source="草稿").project == "t"
    with pytest.raises(ConfigError, match="草稿 校验失败"):
        parse_project_rules("project: t\n", source="草稿")
    with pytest.raises(ConfigError, match="顶层必须是映射"):
        parse_project_rules("- a\n- b\n", source="草稿")
    bomb = "a: &x [1, 2]\nb: [*x, *x]\n"
    with pytest.raises(ConfigError, match="别名"):
        parse_project_rules(bomb, source="草稿", allow_aliases=False)


def test_booster_category(tmp_path: Path) -> None:
    data = _minimal()
    data["sets"]["scam"] = {"role": "booster", "category": "fraud_scam", "terms": ["loan offer"]}
    rules = load_project_rules(_write(tmp_path, data))
    assert rules.booster_category("scam") == "fraud_scam"
    assert rules.booster_category("brand") is None
    data["sets"]["brand"]["category"] = "fraud_scam"
    with pytest.raises(ConfigError, match="category"):
        load_project_rules(_write(tmp_path, data))
