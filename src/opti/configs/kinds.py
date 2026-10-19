# src/opti/configs/kinds.py
"""配置类型注册表（设计 2026-10-12-web-config-phase1/2/3）：解析、校验、YAML 与结构化数据互转、来源文件与密钥名单。

文件与 Web 提交共用同一套校验；新增一类配置只需在 REGISTRY 中登记。
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel, ValidationError

from opti.alerting.config import ENV_FALLBACK as ALERTING_ENV
from opti.alerting.config import AlertingConfig
from opti.alerting.config import secret_names as alerting_secret_names
from opti.configs import connectors as connector_overrides
from opti.configs.identity import IdentityConfig
from opti.configs.identity import read_file as read_identity
from opti.core.config import ConfigError, ProjectRules, reject_aliases
from opti.core.kev import SoftwareList
from opti.core.policy import OperationsConfig
from opti.core.vendors import VendorList
from opti.organization import Organization, OrganizationInvalid, parse_organization
from opti.pipeline.campaigns import CampaignConfig
from opti.pipeline.retention import RetentionConfig
from opti.settings import Settings
from opti.sharing import SharingConfig
from opti.siem import siem_problems
from opti.takedown.config import TakedownConfig
from opti.takedown.templates import TakedownTemplates, dump_templates, templates_from_dir
from opti.tickets.config import TicketsConfig

KindName = Literal[
    "rules",
    "organization",
    "alerting",
    "retention",
    "campaigns",
    "takedown",
    "takedown_templates",
    "tickets",
    "vendors",
    "software",
    "sharing",
    "connectors",
    "identity",
    "operations",
]
_ALLOWED_CONTROL = {"\n", "\r", "\t"}


class ConfigInvalid(Exception):
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        super().__init__("；".join(str(e["message"]) for e in errors))
        self.errors = errors


def _error(message: str, path: str = "", line: int | None = None) -> ConfigInvalid:
    return ConfigInvalid([{"path": path, "message": message, "line": line}])


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check_text(max_bytes: int, text: str) -> None:
    if len(text.encode("utf-8")) > max_bytes:
        raise _error(f"内容超过 {max_bytes // 1000} KB")
    if any(ord(c) < 32 and c not in _ALLOWED_CONTROL for c in text):
        raise _error("内容含控制字符")


def _path(loc: tuple[int | str, ...]) -> str:
    out = ""
    for part in loc:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


def _pydantic(e: ValidationError) -> ConfigInvalid:
    return ConfigInvalid([
        {"path": _path(tuple(err["loc"])), "message": str(err["msg"]).removeprefix("Value error, "), "line": None}
        for err in e.errors()
    ])  # fmt: skip


def _load_yaml(text: str, *, allow_aliases: bool) -> Any:
    try:
        if not allow_aliases:
            reject_aliases(text, "配置")
        return yaml.safe_load(text)
    except ConfigError as e:
        raise _error(str(e)) from None
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        problem = getattr(e, "problem", None) or str(e)
        raise _error(f"YAML 语法错误：{problem}", line=mark.line + 1 if mark else None) from None


def _dump(data: Mapping[str, Any]) -> str:
    return yaml.safe_dump(dict(data), sort_keys=False, allow_unicode=True, default_flow_style=False)


@dataclass(frozen=True)
class Kind:
    name: str
    max_bytes: int
    path: Callable[[Settings], Path]
    parse_text: Callable[[str, bool], Any]  # (文本, 是否允许 YAML 别名) → 模型；抛 ConfigInvalid
    to_data: Callable[[Any], dict[str, Any]]
    from_data: Callable[[dict[str, Any]], str]  # 结构化数据 → 规范化 YAML；抛 ConfigInvalid
    read_file: Callable[[Settings], str]
    secret_names: Callable[[Any], set[str]] | None = None
    env_fallback: Mapping[str, str] = field(default_factory=dict)
    problems: Callable[[Any, Mapping[str, str | None]], list[str]] | None = None
    # 快照只带库中真正存了的密钥（含显式清除）；环境变量兜底交给读取方（连接器的 EnvSecretProvider）
    stored_only: bool = False
    has_file: bool = True  # False：没有来源文件，v0 即默认值


def model_kind(
    name: str,
    model: type[BaseModel],
    *,
    max_bytes: int,
    path: Callable[[Settings], Path],
    missing_ok: bool = True,
    exclude_defaults: bool = False,
    secret_names: Callable[[Any], set[str]] | None = None,
    env_fallback: Mapping[str, str] | None = None,
    problems: Callable[[Any, Mapping[str, str | None]], list[str]] | None = None,
) -> Kind:
    """YAML 顶层为映射、由一个 pydantic 模型校验的配置。"""

    def parse_text(text: str, allow_aliases: bool) -> Any:
        raw = _load_yaml(text, allow_aliases=allow_aliases) if text.strip() else {}
        if not isinstance(raw, dict):
            raise _error("顶层必须是映射（mapping）")
        try:
            return model.model_validate(raw)
        except ValidationError as e:
            raise _pydantic(e) from None

    def to_data(m: Any) -> dict[str, Any]:
        return cast(dict[str, Any], m.model_dump(mode="json"))

    def from_data(data: dict[str, Any]) -> str:
        try:
            m = model.model_validate(data)
        except ValidationError as e:
            raise _pydantic(e) from None
        return _dump(m.model_dump(mode="json", exclude_defaults=exclude_defaults))

    def read_file(settings: Settings) -> str:
        p = path(settings)
        if missing_ok and not p.exists():
            return ""
        return p.read_text(encoding="utf-8")

    return Kind(name, max_bytes, path, parse_text, to_data, from_data, read_file,
                secret_names, dict(env_fallback or {}), problems)  # fmt: skip


def _organization_kind() -> Kind:
    def parse_text(text: str, allow_aliases: bool) -> Organization:
        if text.strip():
            try:
                yaml.safe_load(text)
            except yaml.YAMLError as e:
                mark = getattr(e, "problem_mark", None)
                problem = getattr(e, "problem", None) or str(e)
                raise _error(
                    f"YAML 语法错误：{problem}", line=mark.line + 1 if mark else None
                ) from None
        try:
            return parse_organization(text)
        except OrganizationInvalid as e:
            raise _error(str(e), path=e.field) from None

    def from_data(data: dict[str, Any]) -> str:
        text = _dump(data)
        parse_text(text, False)
        return text

    def read_file(settings: Settings) -> str:
        p = settings.organization_path
        return p.read_text(encoding="utf-8") if p.exists() else ""

    return Kind("organization", 16_000, lambda s: s.organization_path, parse_text,
                lambda m: dataclasses.asdict(m), from_data, read_file)  # fmt: skip


def _templates_kind() -> Kind:
    def parse_text(text: str, allow_aliases: bool) -> TakedownTemplates:
        raw = (
            _load_yaml(text, allow_aliases=allow_aliases)
            if text.strip()
            else templates_from_dir(Settings().takedown_templates).data()
        )
        if not isinstance(raw, dict):
            raise _error("顶层必须是映射（mapping）")
        try:
            return TakedownTemplates.model_validate(raw)
        except ValidationError as e:
            raise _pydantic(e) from None

    def from_data(data: dict[str, Any]) -> str:
        try:
            model = TakedownTemplates.model_validate(data)
        except ValidationError as e:
            raise _pydantic(e) from None
        return dump_templates(model.data())

    return Kind(
        "takedown_templates",
        200_000,
        lambda s: s.takedown_templates,
        parse_text,
        lambda m: m.data(),
        from_data,
        lambda s: dump_templates(templates_from_dir(s.takedown_templates).data()),
    )


def _connectors_kind() -> Kind:
    base = model_kind(
        "connectors", connector_overrides.ConnectorOverrides, max_bytes=256_000,
        path=lambda s: s.state_dir / "connectors.yaml",  # 没有来源文件：v0 即空文档
        exclude_defaults=True,
    )  # fmt: skip

    def parse_text(text: str, allow_aliases: bool) -> Any:
        model = base.parse_text(text, allow_aliases)
        if errors := connector_overrides.problems(model):
            raise ConfigInvalid(errors)
        return model

    def from_data(data: dict[str, Any]) -> str:
        text = base.from_data(data)
        parse_text(text, False)
        return text

    return dataclasses.replace(
        base,
        parse_text=parse_text,
        from_data=from_data,
        read_file=lambda _s: "",
        secret_names=lambda _m: connector_overrides.credential_names(),
        stored_only=True,
        has_file=False,
    )


TICKETS_ENV = {
    "webhook_url": "OPTI_SECRET_TICKETS_WEBHOOK_URL",
    "signing_key": "OPTI_SECRET_TICKETS_SIGNING_KEY",
    "jira_api_token": "OPTI_SECRET_TICKETS_JIRA_API_TOKEN",
    "servicenow_password": "OPTI_SECRET_TICKETS_SERVICENOW_PASSWORD",
    "servicenow_client_secret": "OPTI_SECRET_TICKETS_SERVICENOW_CLIENT_SECRET",
}


REGISTRY: dict[str, Kind] = {
    k.name: k
    for k in (
        model_kind("rules", ProjectRules, max_bytes=200_000, path=lambda s: s.rules_path,
                   missing_ok=False, exclude_defaults=True),
        _organization_kind(),
        model_kind("alerting", AlertingConfig, max_bytes=64_000, path=lambda s: s.alerting_config,
                   secret_names=alerting_secret_names, env_fallback=ALERTING_ENV),
        model_kind("retention", RetentionConfig, max_bytes=4_000, path=lambda s: s.retention_config),
        model_kind("campaigns", CampaignConfig, max_bytes=4_000, path=lambda s: s.campaigns_config),
        model_kind("takedown", TakedownConfig, max_bytes=128_000, path=lambda s: s.takedown_config),
        _templates_kind(),
        model_kind("tickets", TicketsConfig, max_bytes=16_000, path=lambda s: s.tickets_config,
                   secret_names=lambda _m: set(TICKETS_ENV), env_fallback=TICKETS_ENV),
        model_kind("vendors", VendorList, max_bytes=256_000, path=lambda s: s.vendors_path),
        model_kind("software", SoftwareList, max_bytes=256_000, path=lambda s: s.software_path),
        model_kind("sharing", SharingConfig, max_bytes=64_000, path=lambda s: s.sharing_config,
                   secret_names=lambda _m: {"siem_signing_key", "siem_webhook_token"},
                   env_fallback={"siem_signing_key": "OPTI_SECRET_SIEM_SIGNING_KEY",
                                 "siem_webhook_token": "OPTI_SECRET_SIEM_WEBHOOK_TOKEN"},
                   problems=lambda model, sec: siem_problems(
                       model.siem, signing_key=sec.get("siem_signing_key"),
                       webhook_token=sec.get("siem_webhook_token"))),
        _connectors_kind(),
        dataclasses.replace(
            model_kind("identity", IdentityConfig, max_bytes=32_000, path=lambda s: s.oidc_config,
                       secret_names=lambda _m: {"client_secret"},
                       env_fallback={"client_secret": "OPTI_SECRET_OIDC_CLIENT_SECRET"}),
            read_file=read_identity,
        ),
        dataclasses.replace(
            model_kind("operations", OperationsConfig, max_bytes=64_000,
                       path=lambda s: s.state_dir / "operations.yaml"),
            read_file=lambda _s: "", has_file=False,
        ),
    )
}  # fmt: skip
KINDS: tuple[KindName, ...] = cast(tuple[KindName, ...], tuple(REGISTRY))
MAX_BYTES: dict[str, int] = {k: v.max_bytes for k, v in REGISTRY.items()}


def kind(name: str) -> Kind:
    return REGISTRY[name]


def parse(kind_name: str, text: str, *, allow_aliases: bool = False) -> Any:
    k = REGISTRY[kind_name]
    _check_text(k.max_bytes, text)
    return k.parse_text(text, allow_aliases)


def default(kind_name: str) -> Any:
    return REGISTRY[kind_name].parse_text("", True)


def to_data(kind_name: str, model: Any) -> dict[str, Any]:
    return REGISTRY[kind_name].to_data(model)


def from_data(kind_name: str, data: dict[str, Any]) -> str:
    text = REGISTRY[kind_name].from_data(data)
    parse(kind_name, text)  # 体积与控制字符
    return text


def file_path(kind_name: str, settings: Settings) -> Path:
    return REGISTRY[kind_name].path(settings)


def read_file(kind_name: str, settings: Settings) -> str:
    return REGISTRY[kind_name].read_file(settings)
