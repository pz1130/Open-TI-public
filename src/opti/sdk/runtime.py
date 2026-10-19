"""连接器的创建与运行（S1-B 的命令行运行时；S1-C 由 Taskiq 调度器取代 collect）。"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx

from opti.core.config import ProjectRules
from opti.sdk.base import BaseConnector, Enricher
from opti.sdk.context import (
    ConnectorContext,
    CursorStore,
    EnvSecretProvider,
    JsonFileCursorStore,
    ProjectCursorStore,
    SecretProvider,
)
from opti.sdk.http import HttpPolicy, RateLimitedHttpClient
from opti.sdk.manifest import validate_instance_config
from opti.sdk.models import QueryPlan, RawItem
from opti.sdk.registry import Registry, gate, load_instance_config


@dataclass(frozen=True)
class RuntimePaths:
    config_dir: Path = Path("config/connectors")
    state_dir: Path = Path("data")


class ConnectorBlocked(Exception):
    """被合规闸门阻止（未启用、法务未批准、暗网未审批、缺凭据等）。"""


def create(
    registry: Registry,
    connector_id: str,
    rules: ProjectRules,
    *,
    paths: RuntimePaths,
    secrets: SecretProvider | None = None,
    allow_unapproved: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    cursors: CursorStore | None = None,
) -> BaseConnector | Enricher:
    manifest = registry.manifest(connector_id)
    instance = load_instance_config(paths.config_dir, connector_id)
    secrets = secrets or EnvSecretProvider()
    result = gate(manifest, instance, secrets, allow_unapproved=allow_unapproved)
    if not result.runnable:
        raise ConnectorBlocked(result.reason)
    if allow_unapproved and not instance.license_approved:
        print(f"警告：{connector_id} 未经法务批准，仅限开发调试使用", file=sys.stderr)
    config = validate_instance_config(manifest, instance.config)
    plan = manifest.plans.get(instance.plan)
    rate = plan.rate_limit.requests_per_second() if plan else None
    http = RateLimitedHttpClient(HttpPolicy(connector_rate=rate), transport=transport)
    ctx = ConnectorContext(
        connector_id,
        rules,
        http,
        secrets=secrets,
        cursors=ProjectCursorStore(
            cursors or JsonFileCursorStore(paths.state_dir / "cursors.json"), rules.project
        ),
    )
    obj = registry.load_class(connector_id)(ctx, config)
    if isinstance(obj, BaseConnector):
        obj.validate_config()
    return obj


async def collect(
    connector: BaseConnector,
    plan: QueryPlan,
    *,
    max_items: int | None = None,
    seconds: float | None = None,
) -> AsyncIterator[RawItem]:
    """运行连接器，直到产出 max_items 条或超过 seconds 秒。"""
    loop = asyncio.get_running_loop()
    deadline = None if seconds is None else loop.time() + seconds
    source = aiter(connector.fetch(plan))
    count = 0
    try:
        while max_items is None or count < max_items:
            timeout = None if deadline is None else deadline - loop.time()
            if timeout is not None and timeout <= 0:
                break
            try:
                item = await asyncio.wait_for(anext(source), timeout)
            except (StopAsyncIteration, TimeoutError):
                break
            yield item
            count += 1
    finally:
        aclose = getattr(source, "aclose", None)
        if aclose is not None:
            await aclose()
