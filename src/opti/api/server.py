"""研判接口进程：uvicorn。生产环境放在使用机构反向代理（TLS、SSO 网关）之后，只在内网开放（设计文档 18.3）。"""

from __future__ import annotations

import asyncio
import os

import uvicorn
from redis.asyncio import Redis

from opti.alerting.runtime import ticket_source
from opti.api.app import create_api
from opti.api.bootstrap import ensure_superadmin
from opti.api.deps import ApiDeps
from opti.api.oidc.runtime import ConfigBoundOidc
from opti.configs.runtime import ConfigRuntime, RedisRulePublisher, process_name
from opti.core.secretbox import Keyring
from opti.db.engine import make_engine, make_sessionmaker
from opti.pipeline.broker import broker
from opti.pipeline.enrichment import utcnow
from opti.sdk.context import EnvSecretProvider
from opti.sdk.http import RateLimitedHttpClient
from opti.settings import Settings
from opti.storage.objects import object_store_from_settings
from opti.translation import LocalTranslator


def serve_api(settings: Settings) -> None:
    database_url = settings.database_url
    if not database_url:
        raise RuntimeError("研判接口需要 OPTI_DATABASE_URL")

    async def main() -> None:
        secrets = EnvSecretProvider()
        keyring = Keyring.from_env(state_dir=settings.state_dir)
        engine = make_engine(database_url)
        sessions = make_sessionmaker(engine)
        ticket_http = RateLimitedHttpClient()
        oidc_http = RateLimitedHttpClient()
        translator = (
            LocalTranslator(settings.translation_socket)
            if settings.translation_socket is not None
            else None
        )
        edge = (
            Redis.from_url(settings.broker_url, decode_responses=True)
            if settings.broker_url
            else None
        )
        config: ConfigRuntime | None = None
        broker_started = False
        try:
            await ensure_superadmin(sessions, settings.state_dir, utcnow())
            await broker.startup()
            broker_started = True
            # 先读数据库版本；仅在库中无可用版本时才解析初始文件。
            config = await ConfigRuntime.start(
                settings, sessions, process=process_name("api"),
                publisher=RedisRulePublisher(edge) if edge is not None else None,
                keyring=keyring,
            )  # fmt: skip
            deps = ApiDeps(
                settings=settings,
                config=config,
                sessions=sessions,
                store=object_store_from_settings(settings, secrets),
                web_dist=settings.web_dist,
                ticket_source=ticket_source(lambda: deps.config.snapshot, ticket_http),
                translator=translator,
                keyring=keyring,
                edge_store=edge,
                oidc_source=ConfigBoundOidc(lambda: deps.config.snapshot, oidc_http),
            )
            app = create_api(deps)
            config.start_background()
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=settings.api_host,
                    port=settings.api_port,
                    log_level="info",
                    server_header=False,
                    proxy_headers=True,
                    forwarded_allow_ips=os.environ.get("OPTI_FORWARDED_ALLOW_IPS", "127.0.0.1"),
                )
            )
            await server.serve()
        finally:
            if config is not None:
                await config.stop()
            if broker_started:
                await broker.shutdown()
            await ticket_http.aclose()
            await oidc_http.aclose()
            if translator is not None:
                await translator.close()
            if edge is not None:
                await edge.aclose()
            await engine.dispose()

    asyncio.run(main())
