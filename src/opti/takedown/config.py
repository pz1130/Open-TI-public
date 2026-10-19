"""下架渠道配置（config/takedown/platforms.yaml）：CDN 识别、并行举报、社交平台、升级渠道与 SLA。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TargetKind = Literal["registrar", "hosting", "cdn", "report", "platform"]
_ID = r"^[a-z0-9_.-]{1,64}$"
_HOST = re.compile(r"(?=.{1,253}\Z)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\Z")


class Channel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    email: str | None = None
    url: str | None = None

    @model_validator(mode="after")
    def _needs_one(self) -> Channel:
        if not (self.email or self.url):
            raise ValueError("投诉渠道需要 email 或 url")
        return self


class Provider(BaseModel):
    """CDN / 反向代理：按名称服务器后缀或托管 IP 的 RDAP 网络名称（前缀）、所属机构识别。"""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=_ID)
    name: str
    nameservers: tuple[str, ...] = ()
    network_names: tuple[str, ...] = ()
    orgs: tuple[str, ...] = ()
    channel: Channel
    note: str = ""


class ReportChannel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=_ID)
    name: str
    tlds: tuple[str, ...] = ()  # 为空表示所有域名；国际化顶级域写 Punycode
    channel: Channel
    note: str = ""


class Platform(BaseModel):
    """平台自有域名；名单内链接只用人工上传证据，不交给沙箱访问。"""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=_ID)
    name: str
    hosts: tuple[str, ...] = Field(min_length=1)
    channel: Channel | None = None
    note: str = ""

    @field_validator("hosts")
    @classmethod
    def _lowercase_domains(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        for host in hosts:
            if not _HOST.fullmatch(host):
                raise ValueError(f"平台主机应为小写域名（不含协议、通配符）：{host}")
        return hosts

    def owns(self, host: str) -> bool:
        value = host.lower().rstrip(".")
        return any(value == domain or value.endswith("." + domain) for domain in self.hosts)


class Escalation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: TargetKind
    name: str
    channel: Channel
    note: str = ""


def _default_sla() -> dict[str, int]:
    return {"registrar": 72, "hosting": 48, "cdn": 48, "report": 0, "platform": 72}


class TakedownConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    sla_hours: dict[str, int] = Field(default_factory=_default_sla)
    max_reminders: int = Field(default=3, ge=1, le=10)
    providers: tuple[Provider, ...] = ()
    reporting: tuple[ReportChannel, ...] = ()
    platforms: tuple[Platform, ...] = ()
    escalation: tuple[Escalation, ...] = ()

    def platform_for(self, host: str | None) -> Platform | None:
        if not host:
            return None
        return next((platform for platform in self.platforms if platform.owns(host)), None)


def load_takedown_config(path: Path) -> TakedownConfig:
    if not path.exists():
        return TakedownConfig()
    return TakedownConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
