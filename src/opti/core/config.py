"""加载与校验项目关键词规则（config/projects/<project>/keywords.yaml，设计文档 7.2）。"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

Role = Literal["match", "booster", "negative"]


class ConfigError(Exception):
    """配置文件缺失、格式错误或未通过合规校验。"""


class ContextRule(BaseModel):
    """共现约束：命中词前后 window_chars 个字符内必须出现 terms 之一。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    window_chars: int = Field(gt=0, le=2000)
    terms: tuple[str, ...] = Field(min_length=1)


class Term(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str = Field(min_length=1)
    mode: Literal["phrase", "token"] = "phrase"
    case_sensitive: bool = False
    # 是否允许下发到外部数据源检索；太短或太敏感的词只做本地匹配
    remote_search: bool = True
    # 繁体变体由归一化（繁转简）统一处理，此字段仅作说明保留
    variants: Literal["auto_traditional"] | None = None
    require_any_within: ContextRule | None = None


class TermSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    weight: float = Field(default=1.0, ge=0, le=1)
    role: Role = "match"
    type: Literal["brand", "executive", "product", "supplier", "other"] = "brand"
    approval_ref: str | None = None
    category: Literal["fraud_scam", "negative_press"] | None = None
    private: bool = False  # 仅本地匹配，不下发外部数据源或模型
    terms: tuple[Term, ...] = Field(min_length=1)

    @field_validator("terms", mode="before")
    @classmethod
    def _coerce_strings(cls, v: object) -> object:
        if isinstance(v, list):
            return [{"value": t} if isinstance(t, str) else t for t in v]
        return v

    @model_validator(mode="after")
    def _executive_needs_approval(self) -> TermSet:
        if self.type == "executive" and not (self.approval_ref and self.approval_ref.strip()):
            raise ValueError(
                "人员类关键词集合（type: executive）必须填写 approval_ref"
                "（DPO/法务审批编号，见设计文档 2.1）"
            )
        return self

    @model_validator(mode="after")
    def _category_only_for_boosters(self) -> TermSet:
        if self.category is not None and self.role != "booster":
            raise ValueError("category 只能用于 role: booster 的集合")
        return self


class DomainRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    official: tuple[str, ...] = Field(min_length=1)
    known_lookalikes: tuple[str, ...] = ()
    brand_tokens: tuple[str, ...] = Field(min_length=1)
    combo_affixes: tuple[str, ...] = ()
    fraud_affixes: tuple[str, ...] = ()
    # 受限品牌词：只在与指定词缀组合时命中（如 orbit + fund），避免 exorbitant、orbit-music 之类误报
    restricted_tokens: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    # 长度不超过此值的品牌词只做整词/词缀匹配，不做子串或模糊匹配（设计文档 7.3）
    short_token_max_len: int = Field(default=4, ge=1, le=10)

    @field_validator("restricted_tokens")
    @classmethod
    def _normalize_restricted(cls, v: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        out: dict[str, tuple[str, ...]] = {}
        for token, affixes in v.items():
            key = token.strip().lower()
            values = tuple(a.strip().lower() for a in affixes)
            if not key or not values or any(not a for a in values):
                raise ValueError("restricted_tokens 的品牌词和词缀都不能为空")
            out[key] = values
        return out

    @field_validator(
        "official", "known_lookalikes", "brand_tokens", "combo_affixes", "fraud_affixes"
    )
    @classmethod
    def _normalize(cls, v: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
        normalized = tuple(x.strip().lower().rstrip(".") for x in v)
        field = info.field_name or "域名"
        if any(item == "" for item in normalized):
            raise ValueError(f"{field} 在规范化后为空")
        return normalized


class ProjectRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    project: str = Field(min_length=1)
    authorization_ref: str
    languages: tuple[str, ...] = ("en",)
    sets: dict[str, TermSet]
    domains: DomainRules

    @field_validator("authorization_ref")
    @classmethod
    def _authorization_required(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("authorization_ref 必填：项目上线前须取得书面授权（设计文档 2.1）")
        return v

    @model_validator(mode="after")
    def _negative_set_needs_negative_role(self) -> ProjectRules:
        named = self.sets.get("negative")
        if named is not None and named.role != "negative":
            raise ValueError("名为 negative 的集合必须把 role 设为 negative")
        # 漏写 type 会让人员关键词被当作品牌词：绕过 DPO 审批校验并被下发到外部数据源（设计文档 2.1、2.5）
        executives = self.sets.get("executives")
        if executives is not None and executives.type != "executive":
            raise ValueError("名为 executives 的集合必须把 type 设为 executive")
        return self

    def sets_with_role(self, role: Role) -> list[tuple[str, TermSet]]:
        return [(name, s) for name, s in self.sets.items() if s.role == role]

    def booster_category(self, set_name: str) -> str | None:
        term_set = self.sets.get(set_name)
        return term_set.category if term_set is not None and term_set.role == "booster" else None


def reject_aliases(text: str, source: str) -> None:
    """拒绝 YAML 锚点/别名：草稿来自网页输入，别名可以把很小的文本展开成巨大的结构（"十亿笑声"）。"""
    depth = 0
    for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader), start=1):
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
        if depth > 32 or count > 10_000:
            raise ConfigError(f"{source} YAML 结构过深或过于复杂")
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise ConfigError(f"{source} 中不允许使用 YAML 锚点/别名")


def parse_project_rules(
    text: str, *, source: str = "规则", allow_aliases: bool = True
) -> ProjectRules:
    try:
        if not allow_aliases:
            reject_aliases(text, source)
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"{source} 不是合法的 YAML：{e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"{source} 顶层必须是映射（mapping）")
    try:
        return ProjectRules.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(f"{source} 校验失败：\n{e}") from e


def load_project_rules(path: Path) -> ProjectRules:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"找不到关键词配置文件：{path}") from None
    return parse_project_rules(text, source=str(path))
