"""数据外送配置（设计文档 6.4、12）：STIX 2.1 导出与 SIEM 推送。密钥由配置库或环境变量提供。"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from opti.core.scoring import Severity


class StixSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tlp: Literal["white", "green", "amber", "red"] = "amber"
    min_severity: Severity = Severity.MEDIUM


class SyslogChannel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: bool = False
    host: str = ""
    port: int = Field(default=6514, ge=1, le=65535)
    protocol: Literal["tls", "tcp", "udp"] = "tls"
    ca_file: str = ""  # 接收端使用私有 CA 时填写 CA 证书路径；为空用系统信任库
    ca_pem: str = Field(default="", max_length=64_000)  # 粘贴 PEM 证书；优先于 ca_file
    app_name: str = Field(default="opti", pattern=r"^[A-Za-z0-9._-]{1,48}$")

    @field_validator("ca_pem")
    @classmethod
    def _valid_ca_pem(cls, value: str) -> str:
        if value.strip():
            try:
                ssl.create_default_context(cadata=value)
            except (ssl.SSLError, ValueError) as e:
                raise ValueError(f"CA 证书无法解析（需要 PEM 格式）：{type(e).__name__}") from None
        return value

    @model_validator(mode="after")
    def _host_required(self) -> SyslogChannel:
        if self.enabled and not self.host.strip():
            raise ValueError("启用 Syslog 时必须填写 host")
        return self


class WebhookChannel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: bool = False
    url: str = ""
    format: Literal["json", "splunk_hec"] = "json"
    token_header: str = "Authorization"
    token_prefix: str = ""  # Splunk HEC 填 "Splunk "，Elastic 填 "ApiKey "
    timeout_seconds: float = Field(default=10, gt=0, le=60)

    @model_validator(mode="after")
    def _url_required(self) -> WebhookChannel:
        if self.enabled and not self.url.startswith(("https://", "http://")):
            raise ValueError("启用 Webhook 时 url 必须是 http(s) 地址")
        return self


class SiemSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    min_severity: Severity = Severity.MEDIUM
    categories: tuple[str, ...] = ()  # 为空表示全部类别
    syslog: SyslogChannel = SyslogChannel()
    webhook: WebhookChannel = WebhookChannel()


class SharingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    stix: StixSettings = StixSettings()
    siem: SiemSettings = SiemSettings()


def load_sharing_config(path: Path) -> SharingConfig:
    if not path.exists():
        return SharingConfig()
    return SharingConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
