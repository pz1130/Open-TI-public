# src/opti/takedown/templates.py
"""下架投诉模板（设计 2026-10-12-web-config-phase3）：10 个模板合成一份配置，校验首行与占位符。"""

from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

LANGUAGES = ("zh-CN", "en-US")
TEMPLATE_KINDS = ("registrar", "hosting", "cdn", "report", "platform")
PLACEHOLDERS = frozenset({
    "domain", "url", "ips", "category", "first_seen", "evidence", "detail", "target_name",
    "org_name", "org_short_name", "org_website", "org_contact", "legal_statement", "signature", "date",
})  # fmt: skip
TEMPLATE_MAX = 16_000


def template_errors(text: str) -> list[str]:
    errors: list[str] = []
    if len(text.encode("utf-8")) > TEMPLATE_MAX:
        errors.append("模板超过 16 KB")
    if not text.split("\n", 1)[0].startswith("Subject:"):
        errors.append("第一行必须以 Subject: 开头")
    for m in Template.pattern.finditer(text):
        if m.group("invalid") is not None:
            errors.append("无效的 $ 用法：要写美元符号请用 $$")
            continue
        name = m.group("named") or m.group("braced")
        if name and name not in PLACEHOLDERS:
            errors.append(f"未知的占位符：${name}")
    return list(dict.fromkeys(errors))


class TemplateSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    registrar: str
    hosting: str
    cdn: str
    report: str
    platform: str

    @field_validator("registrar", "hosting", "cdn", "report", "platform")
    @classmethod
    def _valid(cls, v: str) -> str:
        errors = template_errors(v)
        if errors:
            raise ValueError("；".join(errors))
        return v


class TakedownTemplates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    zh_CN: TemplateSet = Field(alias="zh-CN")
    en_US: TemplateSet = Field(alias="en-US")

    def text(self, language: str, kind: str) -> str:
        group = {"zh-CN": self.zh_CN, "en-US": self.en_US}[language]
        return str(getattr(group, kind))

    def data(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True)


def templates_from_dir(path: Path) -> TakedownTemplates:
    return TakedownTemplates.model_validate({
        lang: {kind: (path / lang / f"{kind}.txt").read_text(encoding="utf-8") for kind in TEMPLATE_KINDS}
        for lang in LANGUAGES
    })  # fmt: skip


class _BlockDumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, value: str) -> yaml.Node:
    return dumper.represent_scalar(
        "tag:yaml.org,2002:str", value, style="|" if "\n" in value else None
    )


_BlockDumper.add_representer(str, _str)


def dump_templates(data: dict[str, Any]) -> str:
    """多行模板用 | 块写出，历史 diff 按行可读。"""
    return yaml.dump(data, Dumper=_BlockDumper, sort_keys=False, allow_unicode=True)
