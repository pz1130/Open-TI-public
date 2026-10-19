"""升级时把旧的 data/connector-config.json 导入 kind ``connectors``（设计 2026-10-13-connector-config-in-db）。

校验通过后整份导入，再把文件改名为 .migrated；校验失败时不改文件或数据库。
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti.configs import connector_edits, kinds, revisions
from opti.configs import secrets as config_secrets
from opti.configs.connectors import credential_names, registry
from opti.core.secretbox import Keyring, SecretError
from opti.db import audit

FILE_NAME = "connector-config.json"
NOTE = "从 connector-config.json 导入"


class ImportFailed(Exception):
    pass


@dataclass(frozen=True)
class Imported:
    connectors: int
    secrets: list[str]  # 导入的凭据名（<连接器ID>:<凭据名>），不含内容


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ImportFailed(f"{path} 格式不正确：{type(e).__name__}") from None
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("instances"), dict)
        or not isinstance(data.get("secrets"), dict)
    ):
        raise ImportFailed(f"{path} 格式不正确：应包含 instances 与 secrets 两个映射")
    return data


def _decrypt(data: dict[str, Any], keyring: Keyring | None) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    known = credential_names()
    known_connectors = {manifest.id for manifest in registry().manifests()}
    for cid, values in (data.get("secrets") or {}).items():
        if cid not in known_connectors:
            raise ImportFailed(f"未知的连接器 {cid}")
        if not isinstance(values, dict):
            raise ImportFailed(f"secrets.{cid} 格式不正确：应为凭据映射")
        for name, encoded in values.items():
            key = f"{cid}:{name}"
            if key not in known:
                raise ImportFailed(f"未知的连接器凭据 {key}")
            if encoded is None:
                out[key] = None  # 网页上显式清除过：继续屏蔽环境变量
                continue
            if not isinstance(encoded, str) or not encoded:
                raise ImportFailed(f"secrets.{key} 格式不正确：应为密文字符串或 null")
            if keyring is None:
                raise ImportFailed(
                    f"{FILE_NAME} 含加密的连接器凭据，但服务器没有配置主密钥 OPTI_ENCRYPTION_KEY；"
                    "配置后重新运行 opti db-upgrade"
                )
            try:
                out[key] = keyring.decrypt(
                    base64.b64decode(encoded, validate=True), aad=f"connector:{cid}:{name}"
                )
            except (SecretError, ValueError, binascii.Error) as e:
                raise ImportFailed(
                    f"{key} 无法解密（{e}）：请确认 OPTI_ENCRYPTION_KEY 与写入时相同"
                ) from None
    return out


async def _import(
    s: AsyncSession, data: dict[str, Any], keyring: Keyring | None, now: datetime
) -> Imported:
    secrets = _decrypt(data, keyring)
    instances = data.get("instances") or {}
    try:
        text = kinds.from_data(connector_edits.KIND, {"connectors": instances})
    except kinds.ConfigInvalid as e:
        detail = "；".join(f"{err['path']}：{err['message']}" for err in e.errors)
        raise ImportFailed(f"{FILE_NAME} 中有无效的连接器设置：{detail}") from None
    await revisions.append(
        s, connector_edits.KIND, text, base_version=0, user="system", note=NOTE, now=now
    )
    if secrets:
        await config_secrets.write(
            s, connector_edits.KIND, secrets, keyring=keyring, user="system", now=now
        )
    names = sorted(secrets)
    await audit.append(
        s, actor="system", action="config.imported", now=now,
        detail={"kind": connector_edits.KIND, "connectors": len(instances), "secrets": names},
    )  # fmt: skip
    return Imported(len(instances), names)


async def import_legacy(
    sessions: async_sessionmaker[AsyncSession],
    state_dir: Path,
    keyring: Keyring | None,
    now: datetime,
) -> Imported | None:
    """没有旧文件或已有版本时跳过；校验失败不写库，提交后改名失败会明确报告。"""
    path = state_dir / FILE_NAME
    if not path.exists():
        return None
    async with sessions.begin() as s:
        await connector_edits.lock(s)
        if await revisions.latest(s, connector_edits.KIND) is not None:
            return None
        # 等待锁期间另一进程可能已完成导入并改名。
        if not path.exists():
            return None
        backup = path.with_name(f"{FILE_NAME}.migrated")
        if backup.exists():
            raise ImportFailed(f"{backup} 已存在，请先保留或移走该备份后重试")
        data = _read(path)
        done = await _import(s, data, keyring, now)
    try:
        path.rename(backup)
    except OSError as exc:
        raise ImportFailed(
            f"设置已完整存入数据库，但旧文件无法改名（{type(exc).__name__}）；"
            f"请保留 {path} 并手动改名为 {backup.name}"
        ) from None
    return done
