"""连接器运行时上下文（设计文档 5.3）：框架注入的 HTTP 客户端、密钥、游标与日志。"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from opti.core.config import ProjectRules
from opti.sdk.http import RateLimitedHttpClient


class SecretProvider(Protocol):
    def get(self, connector_id: str, name: str) -> str | None: ...


class EnvSecretProvider:
    """从环境变量读取密钥：OPTI_SECRET_<CONNECTOR_ID>_<NAME>（全大写）。

    SOPS 实现在第一个需要密钥的连接器（S2）中引入，接口不变（设计文档 2.7）。
    """

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._env = environ if environ is not None else os.environ

    def get(self, connector_id: str, name: str) -> str | None:
        if self._env is os.environ:
            from opti.sdk import config_store

            managed, stored = config_store.secret(connector_id, name)
            if managed:
                return stored
        return self._env.get(f"OPTI_SECRET_{connector_id}_{name}".upper()) or None


class CursorStore(Protocol):
    def get(self, connector_id: str, key: str) -> str | None: ...

    def set(self, connector_id: str, key: str, value: str) -> None: ...


class MemoryCursorStore:
    def __init__(self) -> None:
        self._data: dict[tuple[str, str], str] = {}

    def get(self, connector_id: str, key: str) -> str | None:
        return self._data.get((connector_id, key))

    def set(self, connector_id: str, key: str, value: str) -> None:
        self._data[(connector_id, key)] = value

    def dump(self, connector_id: str) -> dict[str, str]:
        """某个连接器的全部游标（随采集任务下发、随结果写回，设计文档 3.4 节点无状态）。"""
        return {k: v for (c, k), v in self._data.items() if c == connector_id}


class ProjectCursorStore:
    """Keep search progress independent even when projects search the same phrase."""

    def __init__(self, store: CursorStore, project: str) -> None:
        self._store = store
        self._prefix = "project:" + hashlib.sha256(project.encode()).hexdigest() + ":"

    def get(self, connector_id: str, key: str) -> str | None:
        return self._store.get(connector_id, self._prefix + key)

    def set(self, connector_id: str, key: str, value: str) -> None:
        self._store.set(connector_id, self._prefix + key, value)


class JsonFileCursorStore:
    """把游标保存在 JSON 文件中（S1-C 改为 PostgreSQL）；写入采用"临时文件 + 原子替换"。"""

    def __init__(self, path: Path) -> None:
        self._path = path

    def _load(self) -> dict[str, dict[str, str]]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}

    def get(self, connector_id: str, key: str) -> str | None:
        return self._load().get(connector_id, {}).get(key)

    def set(self, connector_id: str, key: str, value: str) -> None:
        data = self._load()
        data.setdefault(connector_id, {})[key] = value
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        os.replace(tmp, self._path)


def mask(secret: str) -> str:
    return f"****{secret[-4:]}" if len(secret) > 8 else "****"


class SecretRedactor(logging.Filter):
    """把日志中出现的密钥值替换为掩码（设计文档 2.7、5.5）。"""

    def __init__(self) -> None:
        super().__init__()
        self.secrets: set[str] = set()

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            text = record.getMessage()
            for s in self.secrets:
                text = text.replace(s, mask(s))
            record.msg, record.args = text, ()
        return True


# httpx emits full request URLs at INFO, including PhishTank's key in the
# path. One shared filter avoids adding a transport filter on every context.
_HTTP_REDACTOR = SecretRedactor()
logging.getLogger("httpx").addFilter(_HTTP_REDACTOR)


class ConnectorContext:
    def __init__(
        self,
        connector_id: str,
        rules: ProjectRules,
        http: RateLimitedHttpClient,
        *,
        secrets: SecretProvider | None = None,
        cursors: CursorStore | None = None,
    ) -> None:
        self.connector_id = connector_id
        self.rules = rules
        self._http = http
        self._secrets: SecretProvider = secrets or EnvSecretProvider()
        self._cursors: CursorStore = cursors or MemoryCursorStore()
        self._logger = logging.getLogger(f"opti.connector.{connector_id}")
        self._redactor = SecretRedactor()
        self._logger.addFilter(self._redactor)

    def http(self) -> RateLimitedHttpClient:
        return self._http

    def secret(self, name: str) -> str | None:
        value = self._secrets.get(self.connector_id, name)
        # 审计：只记录读取了哪个密钥，不记录值（S1-C 写入 audit_log）
        self._logger.info("读取密钥 %s（%s）", name, "已配置" if value else "未配置")
        if value:
            self._redactor.secrets.add(value)
            _HTTP_REDACTOR.secrets.add(value)
        return value

    def get_cursor(self, key: str) -> str | None:
        return self._cursors.get(self.connector_id, key)

    def set_cursor(self, key: str, value: str) -> None:
        self._cursors.set(self.connector_id, key, value)

    def logger(self) -> logging.Logger:
        return self._logger
