"""采集网关（设计文档 3.4、18.3）：境外采集节点唯一可访问的境内入口。

只提供采集节点需要的接口；mTLS 在 uvicorn 层完成（server.py），这里再校验节点令牌并识别节点。
"""

import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti.configs.runtime import ConfigRuntime
from opti.gateway import records
from opti.gateway.auth import NodeAuth, overseas_rules, rules_digest
from opti.gateway.jobs import KINDS, JobKind, JobQueue
from opti.pipeline.enrichment import utcnow
from opti.sdk import config_store
from opti.sdk.context import EnvSecretProvider
from opti.sdk.models import RawItem, raw_item_from_dict
from opti.sdk.registry import Registry, gate, load_instance_config
from opti.storage.artifacts import EVIDENCE_TYPES, MAX_ARTIFACT_BYTES, store_saver
from opti.storage.objects import ObjectStore

log = logging.getLogger("opti.gateway")
MAX_ITEMS_PER_BATCH = 500
MAX_BODY_BYTES = 5 * 1024 * 1024
LEASE_WAIT_MAX = 30.0


@dataclass
class GatewayDeps:
    config: ConfigRuntime
    registry: Registry
    auth: NodeAuth
    jobs: JobQueue
    store: ObjectStore
    sessions: async_sessionmaker[AsyncSession]
    enqueue: Callable[[RawItem], Awaitable[None]]
    clock: Callable[[], datetime] = field(default=utcnow)
    config_dir: Path = field(default=Path("config/connectors"))


class LeaseRequest(BaseModel):
    wait: float = Field(default=25.0, ge=0, le=LEASE_WAIT_MAX)
    kinds: list[JobKind] = Field(default_factory=lambda: list(KINDS), min_length=1)


class ItemsRequest(BaseModel):
    items: list[dict[str, Any]] = Field(max_length=MAX_ITEMS_PER_BATCH)


class Heartbeat(BaseModel):
    version: str = Field(max_length=100)
    status: dict[str, Any] = Field(default_factory=dict)


def create_gateway(deps: GatewayDeps) -> FastAPI:
    app = FastAPI(title="Open-TI 采集网关", docs_url=None, redoc_url=None, openapi_url=None)
    cache: dict[str, tuple[str, dict[str, Any]]] = {}

    def current_rules() -> tuple[str, dict[str, Any]]:
        snap = deps.config.snapshot
        hit = cache.get(snap.rules_digest)
        if hit is None:
            doc = overseas_rules(snap.rules)
            hit = (rules_digest(doc), doc)
            cache.clear()
            cache[snap.rules_digest] = hit
        return hit

    allowed = {m.id for m in deps.registry.manifests() if m.egress != "domestic"}

    @app.middleware("http")
    async def limit_body(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in ("POST", "PUT"):
            limit = MAX_ARTIFACT_BYTES if request.url.path == "/v1/evidence" else MAX_BODY_BYTES
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return JSONResponse({"detail": "content-length required"}, status_code=411)
            if int(length) > limit:
                return JSONResponse({"detail": "payload too large"}, status_code=413)
            # Bound actual bytes too: Content-Length alone can be forged in ASGI/proxy requests.
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > limit:
                    return JSONResponse({"detail": "payload too large"}, status_code=413)
            request._body = bytes(body)
        return await call_next(request)

    async def node_id(authorization: Annotated[str | None, Header()] = None) -> str:
        node = deps.auth.identify(authorization)
        if node is None:
            raise HTTPException(401, "invalid node token")
        return node

    Node = Annotated[str, Depends(node_id)]

    @app.get("/v1/rules")
    async def get_rules(node: Node) -> dict[str, Any]:
        digest, doc = current_rules()
        return {"digest": digest, "rules": doc}

    @app.get("/v1/connector-config")
    async def connector_config(node: Node, response: Response) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        instances: dict[str, Any] = {}
        secrets: dict[str, Any] = {}
        for manifest in deps.registry.manifests():
            if manifest.egress == "domestic":
                continue
            instance = load_instance_config(deps.config_dir, manifest.id)
            instances[manifest.id] = instance.model_dump()
            if instance.enabled and instance.license_approved:
                secrets[manifest.id] = config_store.managed_secrets(manifest.id)
        return {
            "instances": instances,
            "secrets": secrets,
            "page_policy": deps.config.snapshot.operations.pages.model_dump(mode="json"),
        }

    @app.post("/v1/jobs/lease")
    async def lease(req: LeaseRequest, node: Node) -> Response:
        job = await deps.jobs.lease(node, req.wait, req.kinds)
        if job is None:
            return Response(status_code=204)
        if job.kind == "run_connector":
            async with deps.sessions() as s, s.begin():
                await records.mark_run_leased(s, int(job.payload["run_id"]), node)
        return JSONResponse(job.to_dict())

    @app.post("/v1/jobs/{job_id}/result", status_code=204)
    async def result(job_id: str, body: Annotated[dict[str, Any], Body()], node: Node) -> Response:
        job = await deps.jobs.leased(job_id, node)
        if job is None:
            raise HTTPException(409, "job not leased by this node")
        if job.kind == "run_connector":
            async with deps.sessions() as s, s.begin():
                await records.finish_dispatched_run(
                    s, int(job.payload["run_id"]), body, deps.clock()
                )
        await deps.jobs.complete(job_id, node, body)
        return Response(status_code=204)

    @app.post("/v1/items")
    async def items(req: ItemsRequest, node: Node) -> dict[str, int]:
        parsed: list[RawItem] = []
        for d in req.items:
            try:
                item = raw_item_from_dict(d)
            except (KeyError, TypeError, ValueError) as e:
                raise HTTPException(422, "malformed item") from e
            if item.connector_id not in allowed:
                raise HTTPException(403, f"connector not allowed: {item.connector_id}")
            if item.connector_id in ("canary", "public_report"):
                result = gate(
                    deps.registry.manifest(item.connector_id),
                    load_instance_config(deps.config_dir, item.connector_id),
                    EnvSecretProvider(),
                )
                if not result.runnable:
                    raise HTTPException(403, "push connector blocked")
            projects = {deps.config.snapshot.rules.project}
            if item.project_ids and not set(item.project_ids) <= projects:
                # A manual scan can arrive before this gateway's next background refresh.
                await deps.config.refresh()
                projects = {deps.config.snapshot.rules.project}
            if not item.project_ids or not set(item.project_ids) <= projects:
                raise HTTPException(403, "unknown project")
            # 记录来自哪个采集节点（证据链）；不影响 item_id
            parsed.append(replace(item, payload={**item.payload, "collector_node": node}))
        for item in parsed:
            await deps.enqueue(item)
        return {"accepted": len(parsed)}

    @app.put("/v1/evidence")
    async def evidence(
        request: Request,
        node: Node,
        sha256: Annotated[str, Query(pattern=r"^[0-9a-f]{64}$")],
        content_type: Annotated[str, Query(max_length=100)],
    ) -> dict[str, Any]:
        media = content_type.split(";")[0].strip().lower()
        if media not in EVIDENCE_TYPES:
            raise HTTPException(415, "unsupported evidence type")
        data = await request.body()
        if len(data) > MAX_ARTIFACT_BYTES:
            raise HTTPException(413, "evidence too large")
        if hashlib.sha256(data).hexdigest() != sha256:
            raise HTTPException(400, "sha256 mismatch")
        return await store_saver(deps.store, node_id=node)(data, media)

    @app.post("/v1/heartbeat", status_code=204)
    async def heartbeat(hb: Heartbeat, node: Node) -> Response:
        async with deps.sessions() as s, s.begin():
            await records.upsert_collector_node(
                s, node, version=hb.version, status=hb.status, now=deps.clock()
            )
        return Response(status_code=204)

    return app
