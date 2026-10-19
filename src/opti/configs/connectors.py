"""连接器网页覆盖（设计 2026-10-13-connector-config-in-db）：只记录网页上改过的连接器，整项替换 YAML。"""

from __future__ import annotations

import functools
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from opti.sdk.manifest import ManifestError, validate_instance_config
from opti.sdk.registry import InstanceConfig, Registry


class ConnectorOverrides(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    connectors: dict[str, InstanceConfig] = Field(default_factory=dict)


@functools.cache
def registry() -> Registry:
    return Registry()


def problems(model: ConnectorOverrides) -> list[dict[str, Any]]:
    """连接器 ID、套餐与参数按 manifest 校验；批准文号只在批准接口里检查。"""
    errors: list[dict[str, Any]] = []
    for cid, instance in model.connectors.items():
        try:
            manifest = registry().manifest(cid)
        except ManifestError:
            errors.append({"path": f"connectors.{cid}", "message": "未知连接器", "line": None})
            continue
        if instance.plan not in manifest.plans:
            errors.append({"path": f"connectors.{cid}.plan", "message": "未知套餐", "line": None})
        try:
            validate_instance_config(manifest, instance.config)
        except ManifestError as e:
            errors.append({"path": f"connectors.{cid}.config", "message": str(e), "line": None})
    return errors


def credential_names() -> set[str]:
    """全部连接器声明的凭据（含套餐要求的），键名为 <连接器ID>:<凭据名>。"""
    return {
        f"{m.id}:{name}"
        for m in registry().manifests()
        for name in {c.name for c in m.credentials}
        | {n for p in m.plans.values() for n in p.requires}
    }


def nested(values: dict[str, str | None]) -> dict[str, dict[str, str | None]]:
    """config_secret 的平铺键名（<id>:<name>）→ 按连接器分组。"""
    out: dict[str, dict[str, str | None]] = {}
    for key, value in values.items():
        cid, _, name = key.partition(":")
        out.setdefault(cid, {})[name] = value
    return out
