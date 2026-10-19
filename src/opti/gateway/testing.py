from typing import Any

import httpx
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker

from opti.configs.runtime import ConfigRuntime
from opti.core.config import ProjectRules
from opti.gateway.app import GatewayDeps
from opti.gateway.auth import NodeAuth
from opti.gateway.jobs import MemoryJobQueue
from opti.sdk.models import RawItem
from opti.sdk.registry import Registry
from opti.storage.objects import MemoryObjectStore

TOKEN = "h" * 40
OTHER_TOKEN = "s" * 40


def make_deps(rules: ProjectRules, **overrides: Any) -> tuple[GatewayDeps, list[RawItem]]:
    enqueued: list[RawItem] = []

    async def enqueue(item: RawItem) -> None:
        enqueued.append(item)

    values: dict[str, Any] = {
        "config": ConfigRuntime.static(rules),
        "registry": Registry(),
        "auth": NodeAuth({"hk1": TOKEN, "sg1": OTHER_TOKEN}),
        "jobs": MemoryJobQueue(),
        "store": MemoryObjectStore(),
        "sessions": async_sessionmaker(),  # 不涉及数据库的测试不会用到
        "enqueue": enqueue,
    }
    values.update(overrides)
    return GatewayDeps(**values), enqueued


def client_for(app: FastAPI, token: str | None = TOKEN) -> httpx.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw", headers=headers
    )
