"""采集网关进程：uvicorn + mTLS（设计文档 3.4、19：采集节点与主平台之间 mTLS）。"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from typing import Any

import uvicorn

from opti.configs.runtime import ConfigRuntime
from opti.db.engine import make_engine, make_sessionmaker
from opti.gateway.app import GatewayDeps, create_gateway
from opti.gateway.auth import NodeAuth
from opti.gateway.jobs import ValkeyJobQueue
from opti.sdk.context import EnvSecretProvider
from opti.sdk.models import RawItem, raw_item_to_dict
from opti.sdk.registry import Registry
from opti.settings import Settings
from opti.storage.objects import object_store_from_settings

Closer = Callable[[], Awaitable[None]]


def ssl_kwargs(settings: Settings) -> dict[str, Any]:
    files = (settings.gateway_tls_cert, settings.gateway_tls_key, settings.gateway_client_ca)
    if not all(files):
        raise RuntimeError(
            "采集网关必须启用 mTLS：需要 OPTI_GATEWAY_TLS_CERT、OPTI_GATEWAY_TLS_KEY、OPTI_GATEWAY_CLIENT_CA"
        )
    cert, key, ca = files
    return {
        "ssl_certfile": str(cert),
        "ssl_keyfile": str(key),
        "ssl_ca_certs": str(ca),
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
    }


async def build_gateway_deps(settings: Settings) -> tuple[GatewayDeps, Closer]:
    if not settings.database_url:
        raise RuntimeError("采集网关需要 OPTI_DATABASE_URL")
    if not settings.broker_url:
        raise RuntimeError("采集网关需要 OPTI_BROKER_URL（Valkey）")
    secrets = EnvSecretProvider()
    store = object_store_from_settings(settings, secrets)
    if store is None:
        raise RuntimeError("采集网关需要 OPTI_S3_ENDPOINT（证据存储）")
    await store.ensure_bucket()
    from opti.pipeline.tasks import ingest  # 延迟导入：任务模块会创建 broker

    async def enqueue(item: RawItem) -> None:
        await ingest.kiq(raw_item_to_dict(item))

    engine = make_engine(settings.database_url)
    sessions = make_sessionmaker(engine)
    jobs = ValkeyJobQueue.from_url(settings.broker_url)
    deps = GatewayDeps(
        config=await ConfigRuntime.start(settings, sessions, process="gateway"),
        registry=Registry(),
        auth=NodeAuth.from_secrets(settings.gateway_nodes, secrets),
        jobs=jobs,
        store=store,
        sessions=sessions,
        enqueue=enqueue,
        config_dir=settings.config_dir,
    )

    async def close() -> None:
        await deps.config.stop()
        await jobs.close()
        await engine.dispose()

    return deps, close


def serve(settings: Settings) -> None:
    async def main() -> None:
        from opti.pipeline.broker import broker

        tls = ssl_kwargs(settings)  # 先检查证书配置，再连接数据库
        deps, close = await build_gateway_deps(settings)
        deps.config.start_background()
        await broker.startup()
        config = uvicorn.Config(
            create_gateway(deps),
            host=settings.gateway_host,
            port=settings.gateway_port,
            log_level="info",
            proxy_headers=False,
            server_header=False,
            **tls,
        )
        try:
            await uvicorn.Server(config).serve()
        finally:
            await broker.shutdown()
            await close()

    asyncio.run(main())
