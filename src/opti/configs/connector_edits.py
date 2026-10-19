"""按单个连接器修改 kind ``connectors``（设计 2026-10-13-connector-config-in-db）。

页面一次只改一个连接器：在咨询锁内读最新版本、只替换这一项，再追加新版本，
所以不同连接器的并发修改不会互相覆盖，也不需要 base_version。
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.configs import kinds, revisions
from opti.configs.connectors import ConnectorOverrides, problems
from opti.sdk.registry import InstanceConfig, load_file_instance

KIND = "connectors"
CONFIG_FIELDS = ("enabled", "plan", "config", "schedule")
APPROVAL_FIELDS = ("license_approved", "license_ref", "darkweb_approval_ref")


@dataclass(frozen=True)
class Saved:
    version: int  # 保存后的当前版本（没有改动时为原版本）
    changed: list[str]  # 这一项改动了的字段
    stored: bool  # 是否追加了新版本
    instance: InstanceConfig


async def lock(session: AsyncSession) -> None:
    """与 revisions.append 用同一把事务级咨询锁（可重入）。"""
    await session.execute(
        select(func.pg_advisory_xact_lock(func.hashtext(f"config_revision:{KIND}")))
    )


async def current_document(
    session: AsyncSession, live: ConnectorOverrides
) -> tuple[ConnectorOverrides, int]:
    """最新版本的文档与版本号；最新版本无法解析时在当前生效的快照上合并。"""
    row = await revisions.latest(session, KIND)
    if row is None:
        return ConnectorOverrides(), 0
    try:
        return kinds.parse(KIND, row.content), row.version
    except kinds.ConfigInvalid:
        return live, row.version


def _structure(text: str) -> ConnectorOverrides | None:
    """只按结构解析某一版，不按当前 manifest 校验：manifest 收紧后，旧版本里别的连接器不合法不影响这一个。"""
    try:
        return ConnectorOverrides.model_validate(yaml.safe_load(text) or {})
    except (yaml.YAMLError, ValidationError):
        return None


def _still_valid(connector_id: str, instance: InstanceConfig) -> bool:
    return not problems(ConnectorOverrides(connectors={connector_id: instance}))


def entry(doc: ConnectorOverrides, connector_id: str, config_dir: Path) -> InstanceConfig:
    """该连接器当前的整项设置：文档里有就用文档，否则是 YAML。"""
    return doc.connectors.get(connector_id) or load_file_instance(config_dir, connector_id)


async def save_entry(
    session: AsyncSession,
    connector_id: str,
    fields: Mapping[str, Any],
    *,
    live: ConnectorOverrides,
    config_dir: Path,
    user: str,
    now: datetime,
    note: str | None = None,
    restored_from: int | None = None,
) -> Saved:
    await lock(session)
    doc, version = await current_document(session, live)
    old = entry(doc, connector_id, config_dir)
    new = InstanceConfig.model_validate({**old.model_dump(), **fields})
    changed = [
        name for name in InstanceConfig.model_fields if getattr(old, name) != getattr(new, name)
    ]
    if not changed:
        return Saved(version, [], False, old)
    data = kinds.to_data(KIND, doc)
    data["connectors"][connector_id] = new.model_dump(mode="json")
    text = kinds.from_data(KIND, data)  # 按 manifest 校验
    row = await revisions.append(
        session, KIND, text, base_version=version, user=user, note=note, now=now,
        restored_from=restored_from,
    )  # fmt: skip
    return Saved(row.version, changed, True, new)


@dataclass(frozen=True)
class Change:
    version: int
    created_by: str
    created_at: datetime
    note: str | None
    restored_from: int | None
    changed: list[str]
    diff: str
    restorable: bool  # 该版的参数与当前不同，可以恢复


def _dump(instance: InstanceConfig) -> list[str]:
    text = yaml.safe_dump(
        instance.model_dump(mode="json"), sort_keys=False, allow_unicode=True,
        default_flow_style=False,
    )  # fmt: skip
    return text.splitlines(keepends=True)


def _params(instance: InstanceConfig) -> tuple[Any, ...]:
    return tuple(getattr(instance, name) for name in CONFIG_FIELDS)


async def history(session: AsyncSession, connector_id: str, config_dir: Path) -> list[Change]:
    """改动过这个连接器的版本（新的在前）；某版不在文档里时它的设置就是 YAML。"""
    base = load_file_instance(config_dir, connector_id)
    rows = list(reversed(await revisions.history(session, KIND)))
    effective: list[tuple[Any, InstanceConfig]] = []
    for row in rows:
        doc = _structure(row.content)
        if doc is None:
            continue  # 无法解析的版本不参与比较
        own = doc.connectors.get(connector_id)
        if own is not None and not _still_valid(connector_id, own):
            continue  # 这个连接器在该版的设置已不符合当前 manifest，不参与比较
        effective.append((row, own or base))
    current = effective[-1][1] if effective else base
    out: list[Change] = []
    previous, previous_version = base, 0
    for row, instance in effective:
        changed = [
            name for name in InstanceConfig.model_fields
            if getattr(previous, name) != getattr(instance, name)
        ]  # fmt: skip
        if changed:
            diff = "".join(
                difflib.unified_diff(
                    _dump(previous),
                    _dump(instance),
                    fromfile=f"v{previous_version}",
                    tofile=f"v{row.version}",
                )
            )
            out.append(
                Change(
                    row.version,
                    row.created_by,
                    row.created_at,
                    row.note,
                    row.restored_from,
                    changed,
                    diff,
                    _params(instance) != _params(current),
                )
            )
        previous, previous_version = instance, row.version
    return list(reversed(out))


async def version_entry(
    session: AsyncSession, connector_id: str, version: int, config_dir: Path
) -> InstanceConfig | None:
    """某个版本里该连接器的整项设置（不在文档里时是 YAML）；版本不存在返回 None。"""
    row = await revisions.get(session, KIND, version)
    if row is None:
        return None
    doc = _structure(row.content)
    if doc is None:
        raise kinds.ConfigInvalid([{"path": "", "message": "该版本无法解析", "line": None}])
    # 只取这一项；它是否仍然合法由保存时按当前 manifest 校验
    return entry(doc, connector_id, config_dir)
