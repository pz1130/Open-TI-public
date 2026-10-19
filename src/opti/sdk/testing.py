"""测试辅助：假时钟、Mock HTTP、测试用连接器。只在测试中使用。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any, ClassVar

import httpx

from opti.core.config import ProjectRules
from opti.sdk.base import BaseConnector, Enricher
from opti.sdk.context import (
    ConnectorContext,
    CursorStore,
    EnvSecretProvider,
    MemoryCursorStore,
    SecretProvider,
)
from opti.sdk.http import HttpPolicy, RateLimitedHttpClient
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

Handler = Callable[[httpx.Request], httpx.Response]


class FakeTime:
    """可控的单调时钟：sleep 不真正等待，只推进时间并记录。"""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_http(
    handler: Handler | None = None,
    *,
    policy: HttpPolicy | None = None,
    time: FakeTime | None = None,
) -> RateLimitedHttpClient:
    t = time or FakeTime()
    transport = httpx.MockTransport(handler or (lambda _req: httpx.Response(404)))
    return RateLimitedHttpClient(
        policy or HttpPolicy(max_retries=1),
        transport=transport,
        clock=t.clock,
        sleep=t.sleep,
        rng=lambda: 1.0,
    )


def make_context(
    rules: ProjectRules,
    *,
    handler: Handler | None = None,
    connector_id: str = "test",
    cursors: CursorStore | None = None,
    secrets: SecretProvider | None = None,
    policy: HttpPolicy | None = None,
    time: FakeTime | None = None,
) -> ConnectorContext:
    return ConnectorContext(
        connector_id,
        rules,
        make_http(handler, policy=policy, time=time),
        secrets=secrets or EnvSecretProvider({}),
        cursors=cursors or MemoryCursorStore(),
    )


class EchoConnector(BaseConnector):
    """测试用连接器：按配置中的 items 逐条产出，每条之前等待 delay 秒。"""

    id: ClassVar[str] = "echo"
    tier: ClassVar[Tier] = Tier.FREE

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        delay = float(self.config.get("delay", 0))
        for i, payload in enumerate(self.config.get("items", [])):
            if delay:
                await asyncio.sleep(delay)
            yield RawItem(
                self.id, str(i), utcnow(), None, dict(payload), project_ids=plan.project_ids
            )
            self.ctx.set_cursor("last", str(i))


def cert_msg(domains: Any, *, issuer_o: str = "Let's Encrypt", sha: str = "aa") -> str:
    """构造一条 certstream-server-go lite 流的 certificate_update 消息。"""
    return json.dumps(
        {
            "message_type": "certificate_update",
            "data": {
                "update_type": "X509LogEntry",
                "cert_index": 1,
                "cert_link": "",
                "seen": 1790000000.5,
                "source": {"name": "Test Log", "url": "https://ct.example/"},
                "leaf_cert": {
                    "all_domains": domains,
                    "issuer": {"O": issuer_o, "CN": "R11", "aggregated": f"/O={issuer_o}/CN=R11"},
                    "subject": {"CN": "x"},
                    "sha256": sha,
                    "fingerprint": "AA:BB",
                    "not_before": 1790000000,
                    "not_after": 1797776000,
                    "serial_number": "01",
                    "extensions": {},
                },
            },
        }
    )


class StaticEnricher(Enricher):
    """测试用富化器：返回配置中的固定数据（或调用函数生成；data 为异常实例时抛出）。"""

    id: ClassVar[str] = "static"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self.calls: list[str] = []

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        self.calls.append(value)
        data = self.config["data"]
        if isinstance(data, Exception):
            raise data
        return dict(data(value) if callable(data) else data)


def static_enricher(
    ctx: ConnectorContext,
    eid: str,
    data: Any,
    *,
    ttl: int = 3600,
    types: tuple[str, ...] = ("domain",),
) -> StaticEnricher:
    cls = type(
        f"Static_{eid}",
        (StaticEnricher,),
        {"id": eid, "cache_ttl_seconds": ttl, "supported_types": types},
    )
    instance = cls(ctx, {"data": data})
    assert isinstance(instance, StaticEnricher)
    return instance
