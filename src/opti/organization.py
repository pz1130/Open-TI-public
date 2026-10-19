"""使用本平台的机构信息（平台面向多个机构、各自部署）：名称、网站、安全联系方式、授权声明。

用于对外请求的 User-Agent（设计文档 2.8）与 S2-C 的投诉材料；代码中不写死任何机构。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Organization:
    name: str = "Open-TI user"
    short_name: str = "Open-TI"
    website: str | None = None
    security_contact: str | None = None  # mailto: 或 https:，写进 User-Agent 便于对方联系
    legal_statement: str = ""  # 投诉材料中的授权声明（S2-C）

    legal_statement_en: str = ""  # 英文投诉材料用；为空时沿用 legal_statement
    takedown_sender: str | None = (
        None  # 下架投诉发件邮箱（写入 .eml 的 From，由使用机构自己的邮箱发送）
    )
    signature: str = ""  # 投诉材料落款；为空时用 name

    def user_agent(self, version: str) -> str:
        contact = self.security_contact or self.website
        return f"Open-TI/{version}" + (f" (+{contact})" if contact else "")


class OrganizationInvalid(ValueError):
    """机构信息不合法；field 为出错字段（无法定位时为空字符串）。"""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


_NULLABLE = ("website", "security_contact", "takedown_sender")


def parse_organization(text: str, *, source: str = "机构信息") -> Organization:
    try:
        raw = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError as e:
        raise OrganizationInvalid("", f"{source} 不是合法的 YAML：{e}") from None
    raw = raw or {}
    if not isinstance(raw, dict):
        raise OrganizationInvalid("", f"{source} 顶层必须是映射")
    allowed = set(Organization.__dataclass_fields__)
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise OrganizationInvalid(unknown[0], f"{source} 含未知字段：{', '.join(unknown)}")
    for key, value in raw.items():
        if value is None and key in _NULLABLE:
            continue
        if not isinstance(value, str) or any(ord(c) < 32 for c in value):
            raise OrganizationInvalid(key, f"{source} 的 {key} 必须是无控制字符的字符串")
    return Organization(**raw)


def load_organization(path: Path) -> Organization:
    if not path.exists():
        return Organization()
    return parse_organization(path.read_text(encoding="utf-8"), source=str(path))


_current: Organization | None = None


def set_current(org: Organization | None) -> None:
    """由 ConfigRuntime 在替换快照时调用；None 表示回到读文件。"""
    global _current
    _current = org


@lru_cache(maxsize=1)
def _file_organization() -> Organization:
    return load_organization(
        Path(os.environ.get("OPTI_ORGANIZATION") or "config/organization.yaml")
    )


def current_organization() -> Organization:
    return _current if _current is not None else _file_organization()
