"""连接器与富化器基类（设计文档 5.3）。"""

from __future__ import annotations

import abc
from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

from opti.sdk.context import ConnectorContext
from opti.sdk.models import HealthStatus, QueryPlan, RawItem, Tier


class MissingCredential(Exception):
    """付费/需要凭据的连接器缺少密钥：框架将其标记为"未配置"并降级，而不是报错刷屏。"""


class BaseConnector(abc.ABC):
    id: ClassVar[str]
    tier: ClassVar[Tier]

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        self.ctx = ctx
        self.config: dict[str, Any] = dict(config)

    def validate_config(self) -> None:  # noqa: B027  默认无需校验，子类按需覆盖
        """检查必需凭据等；缺少时抛 MissingCredential。"""

    async def healthcheck(self) -> HealthStatus:
        return HealthStatus(ok=True)

    def compile_queries(self, plan: QueryPlan) -> list[str]:
        """把数据源无关的 QueryPlan 编译为本数据源的查询语法；不需要查询的连接器返回空列表。"""
        return []

    @abc.abstractmethod
    def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        """增量拉取（实现为 async generator）；必须使用 ctx.http()，必须维护游标，实现幂等。"""


class StreamingConnector(BaseConnector):
    @abc.abstractmethod
    def stream(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        """长连接；连接器自行负责断线重连与退避。"""

    def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        return self.stream(plan)


class Enricher(abc.ABC):
    id: ClassVar[str]
    tier: ClassVar[Tier]
    supported_types: ClassVar[tuple[str, ...]]
    cache_ttl_seconds: ClassVar[int] = 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        self.ctx = ctx
        self.config: dict[str, Any] = dict(config)

    def supports(self, entity_type: str) -> bool:
        return entity_type in self.supported_types

    @abc.abstractmethod
    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        """返回结构化富化结果；失败时返回带 error 字段的结果，而不是抛异常。"""
