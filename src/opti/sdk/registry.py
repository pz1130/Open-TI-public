"""连接器注册表与合规闸门（设计文档 2.2、2.4、2.9，3.3"合规内建"）。

合规检查在框架层统一执行，连接器本身不需要也不应该自行判断能否运行。
"""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from opti.sdk import config_store
from opti.sdk.base import BaseConnector, Enricher
from opti.sdk.context import SecretProvider
from opti.sdk.manifest import ConnectorManifest, ManifestError, load_manifest
from opti.sdk.schedules import valid_cron

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]  # src/opti
BUILTIN_ROOTS: tuple[Path, ...] = (_PACKAGE_ROOT / "connectors", _PACKAGE_ROOT / "enrichers")


class InstanceConfig(BaseModel):
    """config/connectors/<id>.yaml：某个连接器在本部署中的启用状态与参数。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    license_approved: bool = False
    license_ref: str | None = None  # 法务批准编号（许可状态表）
    darkweb_approval_ref: str | None = None  # compliance_officer 审批编号
    plan: str = "free"
    config: dict[str, Any] = Field(default_factory=dict)
    schedule: str | None = None

    @field_validator("schedule")
    @classmethod
    def schedule_valid(cls, value: str | None) -> str | None:
        if value is not None and not valid_cron(value):
            raise ValueError("调度须为五段数字 Cron 表达式（UTC）")
        return value


_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _interpolate(value: Any, env: Mapping[str, str]) -> Any:
    if isinstance(value, str):

        def sub(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            if name in env:
                return env[name]
            if default is None:
                raise ManifestError(f"实例配置引用了未设置的环境变量 {name}")
            return default

        return _ENV_REF.sub(sub, value)
    if isinstance(value, list):
        return [_interpolate(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _interpolate(v, env) for k, v in value.items()}
    return value


def load_instance_config(
    config_dir: Path, connector_id: str, *, env: Mapping[str, str] | None = None
) -> InstanceConfig:
    """当前生效的实例设置：网页覆盖（由配置运行时或采集网关安装）优先，否则读 YAML。"""
    if env is None:
        override = config_store.instance(connector_id)
        if override is not None:
            try:
                return InstanceConfig.model_validate(override)
            except ValidationError as e:
                raise ManifestError(f"连接器 {connector_id} 的 Web 配置不合法：\n{e}") from e
    return load_file_instance(config_dir, connector_id, env=env)


def load_file_instance(
    config_dir: Path, connector_id: str, *, env: Mapping[str, str] | None = None
) -> InstanceConfig:
    """只读 config/connectors/<id>.yaml（网页覆盖之下的基础设置）。"""
    path = config_dir / f"{connector_id}.yaml"
    if not path.exists():
        return InstanceConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = _interpolate(raw, os.environ if env is None else env)
        return InstanceConfig.model_validate(raw)
    except (yaml.YAMLError, ValidationError) as e:
        raise ManifestError(f"{path} 不合法：\n{e}") from e


@dataclass(frozen=True)
class GateResult:
    runnable: bool
    reason: str


def gate(
    manifest: ConnectorManifest,
    instance: InstanceConfig,
    secrets: SecretProvider,
    *,
    allow_unapproved: bool = False,
) -> GateResult:
    if not instance.enabled:
        return GateResult(False, "disabled：实例未启用")
    if not instance.license_approved and not allow_unapproved:
        return GateResult(False, "license_not_approved：法务尚未批准该数据源（设计文档 2.4）")
    if manifest.darkweb and not instance.darkweb_approval_ref:
        return GateResult(
            False, "darkweb_not_approved：暗网连接器需要 compliance_officer 审批（设计文档 2.2）"
        )
    plan = manifest.plans.get(instance.plan)
    if plan is None:
        return GateResult(False, f"unknown_plan：manifest 中没有 {instance.plan} 套餐")
    needed = {c.name for c in manifest.credentials if c.required} | set(plan.requires)
    missing = sorted(n for n in needed if not secrets.get(manifest.id, n))
    if missing:
        return GateResult(False, f"unconfigured：缺少凭据 {', '.join(missing)}")
    return GateResult(True, "ok")


class Registry:
    def __init__(self, roots: Sequence[Path] = BUILTIN_ROOTS) -> None:
        self._manifests: dict[str, ConnectorManifest] = {}
        for root in roots:
            for path in sorted(root.glob("*/connector.yaml")):
                m = load_manifest(path)
                if path.parent.name != m.id:
                    raise ManifestError(f"{path}：目录名必须与 id（{m.id}）一致")
                if m.id in self._manifests:
                    raise ManifestError(f"连接器 id 重复：{m.id}")
                self._manifests[m.id] = m

    def manifests(self) -> list[ConnectorManifest]:
        return [self._manifests[k] for k in sorted(self._manifests)]

    def manifest(self, connector_id: str) -> ConnectorManifest:
        try:
            return self._manifests[connector_id]
        except KeyError:
            raise ManifestError(f"未知连接器：{connector_id}") from None

    def load_class(self, connector_id: str) -> type[BaseConnector] | type[Enricher]:
        m = self.manifest(connector_id)
        module_name, _, attr = m.entrypoint.partition(":")
        cls = getattr(importlib.import_module(module_name), attr, None)
        if not (isinstance(cls, type) and issubclass(cls, BaseConnector | Enricher)):
            raise ManifestError(f"{m.entrypoint} 不是连接器或富化器类")
        if getattr(cls, "id", None) != m.id:
            raise ManifestError(f"{m.entrypoint} 的 id 与 manifest 中的 id（{m.id}）不一致")
        return cls


def readiness(
    registry: Registry,
    config_dir: Path,
    secrets: SecretProvider,
    *,
    ids: Collection[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """各连接器在当前进程环境下能否运行、凭据是否已设置（设计文档 5.4）。只报布尔值，不含密钥。"""
    out: dict[str, dict[str, Any]] = {}
    for m in registry.manifests():
        if ids is not None and m.id not in ids:
            continue
        names = sorted(
            {c.name for c in m.credentials} | {n for p in m.plans.values() for n in p.requires}
        )
        credentials = {n: bool(secrets.get(m.id, n)) for n in names}
        try:
            g = gate(m, load_instance_config(config_dir, m.id), secrets)
        except ManifestError:
            out[m.id] = {
                "runnable": False,
                "reason": "config_invalid：实例配置不合法",
                "credentials": credentials,
            }
            continue
        out[m.id] = {"runnable": g.runnable, "reason": g.reason, "credentials": credentials}
    return out
