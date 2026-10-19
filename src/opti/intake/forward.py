"""入口程序把数据转交给平台：经采集网关（mTLS，入口部署在对外主机时）或直接写任务队列（同一内网时）。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from opti.collector.client import GatewayClient
from opti.sdk.context import EnvSecretProvider
from opti.sdk.models import RawItem, raw_item_to_dict
from opti.sdk.registry import Registry, gate, load_instance_config
from opti.sdk.runtime import ConnectorBlocked
from opti.settings import Settings

Forward = Callable[[RawItem], Awaitable[None]]
Close = Callable[[], Awaitable[None]]


def _allowed(item: RawItem) -> None:
    if item.connector_id not in ("canary", "public_report", "referer_log"):
        raise ConnectorBlocked("不是推送型自有数据源")
    registry = Registry()
    result = gate(
        registry.manifest(item.connector_id),
        load_instance_config(Settings.from_env().config_dir, item.connector_id),
        EnvSecretProvider(),
    )
    if not result.runnable:
        raise ConnectorBlocked(result.reason)


def gateway_forwarder(client: GatewayClient) -> tuple[Forward, Close]:
    async def forward(item: RawItem) -> None:
        _allowed(item)
        if await client.items([raw_item_to_dict(item)]) != 1:
            raise ConnectorBlocked("网关未接受数据")

    async def close() -> None:
        await client.aclose()

    return forward, close


def direct_forwarder() -> tuple[Forward, Close]:
    from opti.pipeline.broker import broker
    from opti.pipeline.tasks import ingest

    async def forward(item: RawItem) -> None:
        _allowed(item)
        await ingest.kiq(raw_item_to_dict(item))

    async def close() -> None:
        await broker.shutdown()

    return forward, close
