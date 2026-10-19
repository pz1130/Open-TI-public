"""测试用的内存键值存储，接口与 redis.asyncio.Redis 的子集一致。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

from opti.configs import kinds
from opti.configs.runtime import ConfigRuntime, KindState


class FakeKV:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self._publish_lock = asyncio.Lock()

    async def get(self, name: str) -> str | None:
        return self.data.get(name)

    async def set(self, name: str, value: str) -> Any:
        self.data[name] = value
        return True

    async def publish_if_newer(self, name: str, version: int, body: str) -> bool:
        async with self._publish_lock:
            previous = self.data.get(name)
            if previous is not None:
                try:
                    old_version = int(json.loads(previous)["version"])
                except (ValueError, KeyError, TypeError):
                    old_version = -1
                if old_version > version:
                    return False
            await self.set(name, body)
            return True

    async def hset(self, name: str, key: str, value: str) -> Any:
        self.hashes.setdefault(name, {})[key] = value
        return 1

    async def hgetall(self, name: str) -> dict[str, str]:
        return dict(self.hashes.get(name, {}))


def override(
    runtime: ConfigRuntime,
    *,
    secrets: Mapping[str, Mapping[str, str | None]] | None = None,
    **models: Any,
) -> None:
    """Replace selected config kinds in a test runtime and notify subscribers."""
    snap = runtime.snapshot
    for name, model in models.items():
        old = snap.states[name]
        digest = kinds.digest_of(
            f"override:{json.dumps(kinds.to_data(name, model), sort_keys=True, default=str)}"
        )
        snap = snap.with_state(name, KindState(model, old.version, digest, old.secrets))
    for name, values in (secrets or {}).items():
        old = snap.states[name]
        digest = kinds.digest_of(f"{old.digest}:{json.dumps(dict(values), sort_keys=True)}")
        snap = snap.with_state(name, KindState(old.model, old.version, digest, dict(values)))
    runtime.apply(snap)
