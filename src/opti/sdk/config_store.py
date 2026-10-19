"""进程内的当前连接器设置（设计 2026-10-13-connector-config-in-db）。

平台进程由配置运行时从数据库安装（kind ``connectors``）；境外采集节点由采集网关下发，只放在内存里。
没有安装时（intake、syslog、无数据库的命令）读取方只用 YAML 与环境变量。
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

_instances: dict[str, dict[str, Any]] | None = None
_secrets: dict[str, dict[str, str | None]] | None = None


def set_current(
    instances: Mapping[str, Mapping[str, Any]], secrets: Mapping[str, Mapping[str, str | None]]
) -> None:
    """instances：连接器 ID → 整项实例设置（替换 YAML）；secrets：连接器 ID → 凭据名 → 值（None 为显式清除）。"""
    global _instances, _secrets
    _instances = {cid: copy.deepcopy(dict(v)) for cid, v in instances.items()}
    _secrets = {cid: dict(v) for cid, v in secrets.items()}


def clear_current() -> None:
    global _instances, _secrets
    _instances = None
    _secrets = None


def instance(connector_id: str) -> dict[str, Any] | None:
    if _instances is None:
        return None
    value = _instances.get(connector_id)
    return copy.deepcopy(value) if value is not None else None


def secret(connector_id: str, name: str) -> tuple[bool, str | None]:
    """(是否由网页或网关管理, 值)；未管理时读取方退回环境变量。"""
    values = (_secrets or {}).get(connector_id, {})
    return name in values, values.get(name)


def managed_secrets(connector_id: str) -> dict[str, str | None]:
    return dict((_secrets or {}).get(connector_id, {}))
