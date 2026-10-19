"""登录设置的文件初始值与 Web 版本；密钥单独加密保存。"""

from __future__ import annotations

import yaml
from pydantic import Field, model_validator

from opti.api.oidc.config import ENTRA_DEFAULTS, OidcConfig
from opti.settings import Settings


class IdentityConfig(OidcConfig):
    local_login: bool = True
    session_hours: int = Field(default=12, ge=1, le=168)
    cookie_secure: bool = True

    @model_validator(mode="before")
    @classmethod
    def entra_defaults(cls, value: object) -> object:
        if isinstance(value, dict) and value.get("provider") == "entra":
            return {**ENTRA_DEFAULTS, **value}
        return value

    @model_validator(mode="after")
    def login_available(self) -> IdentityConfig:
        if not self.local_login and not self.enabled:
            raise ValueError("不能同时关闭本地登录和单点登录")
        if not self.local_login and not (
            self.role_mapping.get("platform_admin") or self.role_mapping.get("superadmin")
        ):
            raise ValueError("关闭本地登录前，须为单点登录配置平台管理员角色映射")
        return self


def read_file(settings: Settings) -> str:
    # 只读取文本，校验在选择版本之后进行；已有有效 Web 版本时，旧 YAML 损坏不能阻止启动。
    text = settings.oidc_config.read_text(encoding="utf-8") if settings.oidc_config.exists() else ""
    if text.rstrip().endswith("\n..."):
        text = text.rstrip()[:-3]
    defaults = {
        "local_login": settings.local_login,
        "session_hours": settings.session_hours,
        "cookie_secure": settings.cookie_secure,
    }
    return text + "\n" + yaml.safe_dump(defaults, allow_unicode=True, sort_keys=False)
