"""告警路由配置（设计文档 9.2、13；Web 配置第二期）：全局报告设置、SMTP 中继与多个推送渠道。

密钥（Teams Webhook、SMTP 账号口令）不在这里：由 opti.configs.secrets 管理。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from opti.core.scoring import Category, Severity

ReportKind = Literal["daily", "weekly", "monthly"]
ALL_REPORTS: tuple[ReportKind, ...] = ("daily", "weekly", "monthly")
CHANNEL_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
EMAIL = re.compile(r"[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+")
MAX_CHANNELS = 20
MAX_RECIPIENTS = 50
# 库中没有该密钥时的环境变量兜底（升级前的配置方式）
ENV_FALLBACK = {
    "smtp_username": "OPTI_SECRET_ALERTING_SMTP_USERNAME",
    "smtp_password": "OPTI_SECRET_ALERTING_SMTP_PASSWORD",
    "channel:teams:webhook_url": "OPTI_SECRET_ALERTING_TEAMS_WEBHOOK_URL",
}


def webhook_secret(channel_id: str) -> str:
    return f"channel:{channel_id}:webhook_url"


class SmtpServer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    host: str = "localhost"
    port: int = Field(default=25, ge=1, le=65535)
    starttls: bool = True
    sender: str = "ti-alerts@localhost"


class Channel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    name: str = Field(min_length=1, max_length=80)
    type: Literal["teams", "email"]
    enabled: bool = True
    severities: tuple[Severity, ...] = ()
    categories: tuple[Category, ...] = ()
    reports: tuple[ReportKind, ...] = ()
    notices: bool = False
    recipients: tuple[str, ...] = Field(default=(), max_length=MAX_RECIPIENTS)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not CHANNEL_ID.fullmatch(v):
            raise ValueError(
                "渠道 ID 只能包含小写字母、数字和连字符，以字母或数字开头，最长 32 个字符"
            )
        return v

    @field_validator("recipients")
    @classmethod
    def _recipients(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        bad = [r for r in v if not EMAIL.fullmatch(r)]
        if bad:
            raise ValueError(f"收件人格式不正确：{', '.join(bad)}")
        return v

    @model_validator(mode="after")
    def _by_type(self) -> Channel:
        if self.type == "teams" and self.recipients:
            raise ValueError("Teams 渠道不能设置收件人")
        if self.type == "email" and self.enabled and not self.recipients:
            raise ValueError("启用的邮件渠道至少需要 1 个收件人")
        return self

    def matches(self, severity: str, category: str) -> bool:
        return (
            self.enabled
            and severity in self.severities
            and (not self.categories or category in self.categories)
        )


class AlertingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    public_base_url: str = "http://localhost:8000"
    digest: tuple[Severity, ...] = (Severity.MEDIUM,)
    report_language: Literal["zh-CN", "en-US"] = "zh-CN"
    report_timezone: str = "UTC"
    smtp: SmtpServer = SmtpServer()
    channels: tuple[Channel, ...] = Field(default=(), max_length=MAX_CHANNELS)

    @model_validator(mode="before")
    @classmethod
    def _legacy(cls, data: Any) -> Any:
        """旧格式（immediate / teams / email）转换为渠道；渠道 ID 沿用原 sink 名，避免重发。"""
        if not isinstance(data, dict) or "channels" in data:
            return data
        if not {"immediate", "teams", "email"} & set(data):
            return data
        out = {k: v for k, v in data.items() if k not in ("immediate", "teams", "email")}
        immediate = data.get("immediate", ["critical", "high"])
        teams = data.get("teams") or {}
        email = data.get("email") or {}
        out["smtp"] = {
            "host": email.get("smtp_host", "localhost"),
            "port": email.get("smtp_port", 25),
            "starttls": email.get("starttls", True),
            "sender": email.get("sender", "ti-alerts@localhost"),
        }
        channels: list[dict[str, Any]] = []
        if teams.get("enabled"):
            channels.append({"id": "teams", "name": "Teams", "type": "teams", "severities": immediate,
                             "reports": list(ALL_REPORTS), "notices": True})  # fmt: skip
        if email.get("enabled") and email.get("recipients"):
            channels.append({"id": "email", "name": "邮件", "type": "email", "severities": immediate,
                             "recipients": email["recipients"], "reports": list(ALL_REPORTS),
                             "notices": True})  # fmt: skip
        out["channels"] = channels
        return out

    @field_validator("public_base_url")
    @classmethod
    def _base_url(cls, v: str) -> str:
        parts = urlsplit(v)
        if (
            parts.scheme not in ("http", "https")
            or not parts.netloc
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "平台访问地址必须是 http:// 或 https:// 开头的绝对地址，不能带查询参数"
            )
        return v.rstrip("/")

    @field_validator("report_timezone")
    @classmethod
    def _valid_timezone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise ValueError(f"无效的时区：{v}") from e
        return v

    @model_validator(mode="after")
    def _consistent(self) -> AlertingConfig:
        ids = [c.id for c in self.channels]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            raise ValueError(f"渠道 ID 重复：{', '.join(dup)}")
        # 升级前的默认发件人没有点分域名；旧配置不写 sender 时仍要能加载。
        sender_ok = (
            bool(EMAIL.fullmatch(self.smtp.sender)) or self.smtp.sender == "ti-alerts@localhost"
        )
        if any(c.type == "email" and c.enabled for c in self.channels) and not (
            self.smtp.host.strip() and sender_ok
        ):
            raise ValueError("启用邮件渠道时必须填写 SMTP 地址和合法的发件人")
        return self


def secret_names(cfg: AlertingConfig) -> set[str]:
    return {"smtp_username", "smtp_password"} | {
        webhook_secret(c.id) for c in cfg.channels if c.type == "teams"
    }


def load_alerting_config(path: Path) -> AlertingConfig:
    if not path.exists():
        return AlertingConfig()
    return AlertingConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
