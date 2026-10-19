"""监视列表『关键词』（设计 2026-10-15-domain-keywords）：在关键词规则的 domains 段上增删一项。

纯函数：输入 ProjectRules，返回修改后的新 ProjectRules；不合法时抛 KeywordInvalid。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from opti.core.config import ProjectRules
from opti.core.domains import parse_domain

KeywordKind = Literal["brand", "restricted", "official", "lookalike"]
Action = Literal["added", "updated", "removed"]

_FIELD = {"brand": "brand_tokens", "official": "official", "lookalike": "known_lookalikes"}
_LABEL = {
    "brand": "品牌词",
    "restricted": "受限品牌词",
    "official": "官方域名",
    "lookalike": "合法第三方",
}
_VERB = {"added": "新增", "updated": "修改", "removed": "删除"}


class KeywordInvalid(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _token(value: str, reason: str = "invalid_token") -> str:
    v = value.strip().lower()
    # Unicode letters/digits include Chinese brand names already accepted by the rules editor.
    if not 2 <= len(v) <= 63 or not v.replace("-", "").isalnum():
        raise KeywordInvalid(reason)
    return v


def _affixes(values: Sequence[str]) -> tuple[str, ...]:
    out = tuple(dict.fromkeys(_token(a, "invalid_affix") for a in values))
    if not out:
        raise KeywordInvalid("invalid_affix")
    return out


def _domain(value: str) -> str:
    parts = parse_domain(value)
    if parts is None:
        raise KeywordInvalid("invalid_domain")
    return parts.registered


def normalize(kind: KeywordKind, value: str) -> str:
    return _domain(value) if kind in ("official", "lookalike") else _token(value)


def _with(rules: ProjectRules, **domains: Any) -> ProjectRules:
    data = rules.model_dump()
    data["domains"].update(domains)
    return ProjectRules.model_validate(data)


def add(
    rules: ProjectRules, kind: KeywordKind, value: str, affixes: Sequence[str] = ()
) -> ProjectRules:
    d = rules.domains
    v = normalize(kind, value)
    key = v.replace("-", "")
    if kind == "restricted":
        if any(t.replace("-", "") == key for t in d.brand_tokens):
            raise KeywordInvalid("token_conflict")
        wanted = _affixes(affixes)
        if v in d.restricted_tokens:
            return rules  # 改词缀走 set_affixes
        if any(t.replace("-", "") == key for t in d.restricted_tokens):
            raise KeywordInvalid("duplicate_token")  # 写法变体会覆盖原项的词缀
        return _with(rules, restricted_tokens={**d.restricted_tokens, v: wanted})
    if kind == "brand":
        if any(t.replace("-", "") == key for t in d.restricted_tokens):
            raise KeywordInvalid("token_conflict")
        if v not in d.brand_tokens and any(t.replace("-", "") == key for t in d.brand_tokens):
            raise KeywordInvalid("duplicate_token")
    if kind == "official" and v in d.known_lookalikes:
        raise KeywordInvalid("domain_conflict")
    if kind == "lookalike" and v in d.official:
        raise KeywordInvalid("domain_conflict")
    field = _FIELD[kind]
    current: tuple[str, ...] = getattr(d, field)
    if v in current:
        return rules
    return _with(rules, **{field: (*current, v)})


def remove(rules: ProjectRules, kind: KeywordKind, value: str) -> ProjectRules:
    d = rules.domains
    v = normalize(kind, value)
    if kind == "restricted":
        if v not in d.restricted_tokens:
            raise KeywordInvalid("not_found")
        return _with(
            rules, restricted_tokens={t: a for t, a in d.restricted_tokens.items() if t != v}
        )
    field = _FIELD[kind]
    current: tuple[str, ...] = getattr(d, field)
    if v not in current:
        raise KeywordInvalid("not_found")
    if kind in ("brand", "official") and len(current) == 1:
        raise KeywordInvalid("last_item")
    return _with(rules, **{field: tuple(x for x in current if x != v)})


def set_affixes(rules: ProjectRules, token: str, affixes: Sequence[str]) -> ProjectRules:
    d = rules.domains
    v = token.strip().lower()
    if v not in d.restricted_tokens:
        raise KeywordInvalid("not_found")
    return _with(rules, restricted_tokens={**d.restricted_tokens, v: _affixes(affixes)})


def describe(action: Action, kind: KeywordKind, value: str) -> str:
    """保存说明，写进规则版本的 note。"""
    return f"监视列表：{_VERB[action]}{_LABEL[kind]} {value}"
