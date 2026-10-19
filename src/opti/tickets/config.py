"""工单推送配置（config/tickets.yaml）。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from opti.core.scoring import Severity

AlertState = Literal["open", "acknowledged", "closed"]
TicketMode = Literal["webhook", "email", "jira", "servicenow"]
MAX_EXTRA_FIELDS = 30
_FIELD_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,99}")
_JIRA_HOST = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net")
# 平台自己设置的字段：extra_fields 不得覆盖（设计 2026-10-16 配置）
JIRA_RESERVED = frozenset({"project", "issuetype", "summary", "description", "priority"})
SERVICENOW_RESERVED = frozenset(
    {"short_description", "description", "urgency", "impact", "correlation_id",
     "correlation_display", "work_notes"}
)  # fmt: skip


def _default_status_map() -> dict[str, AlertState]:
    return {"resolved": "closed", "closed": "closed"}


def _https_base(value: str) -> str:
    v = value.strip().rstrip("/")
    parts = urlsplit(v)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise ValueError("必须是 https:// 开头、不带路径的地址")
    return v


def _extra_fields(value: dict[str, Any], reserved: frozenset[str]) -> dict[str, Any]:
    if len(value) > MAX_EXTRA_FIELDS:
        raise ValueError(f"附加字段最多 {MAX_EXTRA_FIELDS} 项")
    for key in value:
        if not _FIELD_KEY.fullmatch(key):
            raise ValueError(f"字段名不合法：{key}")
        if key in reserved:
            raise ValueError(f"字段由平台设置，不能作为附加字段：{key}")
    return value


class JiraConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    base_url: str
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    project_key: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,9}$")
    issue_type: str = Field(default="Task", min_length=1, max_length=60)
    priority_map: dict[Severity, str] = Field(default_factory=dict)
    extra_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _base(cls, value: str) -> str:
        v = _https_base(value)
        parts = urlsplit(v)
        if parts.port is not None or not _JIRA_HOST.fullmatch(parts.hostname or ""):
            raise ValueError("Jira Cloud 地址必须是 https://<站点>.atlassian.net")
        return v

    @field_validator("priority_map")
    @classmethod
    def _priorities(cls, value: dict[Severity, str]) -> dict[Severity, str]:
        if any(not name.strip() or len(name) > 60 for name in value.values()):
            raise ValueError("优先级名称不能为空且不超过 60 个字符")
        return value

    @field_validator("extra_fields")
    @classmethod
    def _extra(cls, value: dict[str, Any]) -> dict[str, Any]:
        labels = value.get("labels")
        if labels is not None and (
            not isinstance(labels, list) or not all(isinstance(x, str) and x for x in labels)
        ):
            raise ValueError("labels 必须是字符串列表")
        return _extra_fields(value, JIRA_RESERVED)


class UrgencyImpact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    urgency: int = Field(ge=1, le=3)
    impact: int = Field(ge=1, le=3)


class ServiceNowConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    base_url: str
    table: str = Field(default="incident", pattern=r"^[a-z][a-z0-9_]{0,79}$")
    auth: Literal["basic", "oauth"] = "basic"
    username: str | None = Field(default=None, min_length=1, max_length=100)
    client_id: str | None = Field(default=None, min_length=1, max_length=100)
    urgency_impact_map: dict[Severity, UrgencyImpact] = Field(default_factory=dict)
    extra_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _base(cls, value: str) -> str:
        return _https_base(value)

    @field_validator("extra_fields")
    @classmethod
    def _extra(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _extra_fields(value, SERVICENOW_RESERVED)

    @model_validator(mode="after")
    def _account(self) -> ServiceNowConfig:
        if self.auth == "basic" and not self.username:
            raise ValueError("Basic 认证需要填写用户名")
        if self.auth == "oauth" and not self.client_id:
            raise ValueError("OAuth 认证需要填写 client_id")
        return self


class TicketsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: bool = False
    mode: TicketMode = "webhook"
    auto_push: tuple[Severity, ...] = ()
    id_field: str = "ticket_id"
    email_to: tuple[str, ...] = ()
    status_map: dict[str, AlertState] = Field(default_factory=_default_status_map)
    include_accounts: bool = False  # 仅 jira / servicenow：凭据暴露工单是否列出员工邮箱
    proxy: str | None = None  # 仅 jira / servicenow：出口代理
    jira: JiraConfig | None = None
    servicenow: ServiceNowConfig | None = None

    @field_validator("status_map")
    @classmethod
    def _status_map(cls, value: dict[str, AlertState]) -> dict[str, AlertState]:
        if len(value) > 50:
            raise ValueError("状态映射最多 50 项")
        if any(not key.strip() for key in value):
            raise ValueError("工单状态不能为空")
        return value

    @field_validator("proxy")
    @classmethod
    def _proxy(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        parts = urlsplit(value.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("代理地址必须是 http:// 或 https:// 开头")
        return value.strip()

    @model_validator(mode="after")
    def _mode_section(self) -> TicketsConfig:
        if self.mode == "jira" and self.jira is None:
            raise ValueError("推送方式为 jira 时必须填写 jira 段")
        if self.mode == "servicenow" and self.servicenow is None:
            raise ValueError("推送方式为 servicenow 时必须填写 servicenow 段")
        return self


def load_tickets_config(path: Path) -> TicketsConfig:
    if not path.exists():
        return TicketsConfig()
    return TicketsConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
