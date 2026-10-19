"""OIDC 配置（config/oidc.yaml）。签发者、客户端、组与角色映射都由使用机构配置；客户端密钥走环境变量。"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from opti.api.rbac import Role

ASYMMETRIC_ALGS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)
MULTI_TENANT = frozenset({"common", "organizations", "consumers"})
# Entra 预设：用应用角色（roles）而不是组——组多于 200 个时 ID Token 不再携带组（组超额）
ENTRA_DEFAULTS: dict[str, Any] = {
    "roles_claim": "roles",
    "username_claim": "preferred_username",
    "label": "Microsoft Entra ID",
}


class OidcConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: bool = False
    provider: Literal["generic", "entra"] = "generic"
    label: str = ""  # 登录按钮上显示的身份提供方名称
    issuer: str | None = None
    tenant_id: str | None = None  # 仅 Entra：生成签发者并校验 tid
    client_id: str | None = None
    redirect_uri: str | None = None  # 默认 <public_base_url>/api/v1/auth/oidc/callback
    post_logout_redirect_uri: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    username_claim: str = "preferred_username"
    display_name_claim: str = "name"
    email_claim: str = "email"
    roles_claim: str = "groups"
    role_mapping: dict[str, tuple[str, ...]] = Field(
        default_factory=dict
    )  # 平台角色 → 身份提供方中的组 / 应用角色
    allowed_algs: tuple[str, ...] = ("RS256", "PS256", "ES256")
    clock_skew_seconds: int = Field(default=120, ge=0, le=600)
    allow_insecure_http: bool = False  # 只用于本机测试身份提供方

    @property
    def effective_issuer(self) -> str:
        if self.provider == "entra" and self.tenant_id:
            return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
        return self.issuer or ""

    def roles_for(self, values: Iterable[str]) -> list[str]:
        have = set(values)
        return sorted(role for role, wanted in self.role_mapping.items() if have & set(wanted))

    @model_validator(mode="after")
    def _check(self) -> OidcConfig:
        unknown = sorted(set(self.role_mapping) - set(Role.__members__.values()))
        if unknown:
            raise ValueError(f"role_mapping 中有未知角色：{', '.join(unknown)}")
        bad_algs = sorted(set(self.allowed_algs) - ASYMMETRIC_ALGS)
        if bad_algs or not self.allowed_algs:
            raise ValueError(
                f"allowed_algs 只能是非对称签名算法，不允许：{', '.join(bad_algs) or '（空）'}"
            )
        if not self.enabled:
            return self
        if self.provider == "entra":
            if not self.tenant_id or self.tenant_id.lower() in MULTI_TENANT:
                raise ValueError(
                    "Entra 预设需要具体的 tenant_id（不能是 common / organizations / consumers）"
                )
        elif not self.issuer:
            raise ValueError("启用 OIDC 需要 issuer")
        if not self.client_id:
            raise ValueError("启用 OIDC 需要 client_id")
        issuer = urlsplit(self.effective_issuer)
        if issuer.scheme != "https" and not (issuer.scheme == "http" and self.allow_insecure_http):
            raise ValueError("issuer 必须使用 https（仅本机测试可设 allow_insecure_http: true）")
        if (
            not issuer.hostname
            or issuer.username
            or issuer.password
            or issuer.query
            or issuer.fragment
        ):
            raise ValueError("issuer 必须是有效且不含查询参数或片段的 URL")
        if "openid" not in self.scopes:
            raise ValueError("scopes 必须包含 openid")
        return self


def load_oidc_config(path: Path) -> OidcConfig:
    if not path.exists():
        return OidcConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} 顶层必须是映射")
    if raw.get("provider") == "entra":
        raw = {**ENTRA_DEFAULTS, **raw}
    return OidcConfig.model_validate(raw)
