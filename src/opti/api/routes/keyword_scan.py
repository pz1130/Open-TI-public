"""Manual searches from both keyword editing pages, using saved rules only."""

from dataclasses import asdict
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import BackfillOut
from opti.db.models import AuditLog, ConnectorRun
from opti.gateway.records import ACTIVE_RUN
from opti.pipeline import backfill
from opti.pipeline import connectors as connector_catalog
from opti.pipeline.tasks import scan_keywords
from opti.sdk.context import EnvSecretProvider
from opti.sdk.scan import KeywordScan, Scope, scan_plan

router = APIRouter(tags=["rules"])
Runner = Annotated[Principal, Depends(require(Perm.RULES_WRITE))]


class KeywordScanIn(BaseModel):
    scope: Scope
    term: str | None = Field(default=None, min_length=1)
    base_version: int = Field(ge=0)


class ConnectorScanOut(BackfillOut):
    name: str


class KeywordScanOut(BaseModel):
    scan: KeywordScan
    connectors: dict[str, ConnectorScanOut]


@router.post("/rules/scan", status_code=202)
async def request_scan(request: Request, user: Runner, body: KeywordScanIn) -> KeywordScanOut:
    deps = get_deps(request)
    await deps.config.refresh()
    snapshot = deps.config.snapshot
    if body.base_version != snapshot.version("rules"):
        raise HTTPException(
            409, {"reason": "version_conflict", "message": "规则已变化，请刷新并选择已保存的词"}
        )
    # A project switch during this request must not redirect the user's scan to another project.
    if snapshot.rules.project != deps.rules.project:
        raise HTTPException(
            409, {"reason": "project_changed", "message": "监测项目已切换，请刷新页面"}
        )
    spec = KeywordScan(
        project_id=snapshot.rules.project,
        rules_version=body.base_version,
        scope=body.scope,
        term=body.term,
    )
    try:
        scan_plan(snapshot.rules, spec)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if not deps.settings.broker_url:
        raise HTTPException(503, "任务队列未配置，无法安排扫描")
    ids = sorted(
        m.id
        for m in deps.registry.manifests()
        if spec.scope in m.search_inputs and "stream" not in m.kind and "enricher" not in m.kind
    )
    now = deps.clock()
    async with deps.sessions.begin() as s:
        # Serialize manual submissions, including the period before a worker creates its run row.
        await s.execute(select(func.pg_advisory_xact_lock(func.hashtext("opti:keyword_scan"))))
        catalog = {
            r["id"]: r
            for r in await connector_catalog.catalog(
                s,
                deps.registry,
                deps.settings.config_dir,
                EnvSecretProvider(),
                remote=deps.settings.collector_mode == "remote",
                now=now,
            )
        }
        results: dict[str, ConnectorScanOut] = {}
        for cid in ids:
            latest = await s.scalar(
                select(AuditLog)
                .where(
                    AuditLog.action == "rules.scan_queued",
                    AuditLog.target_type == "connector",
                    AuditLog.target_id == cid,
                )
                .order_by(AuditLog.ts.desc(), AuditLog.id.desc())
                .limit(1)
            )
            # A pending request reserves a short window until the worker creates its run.
            # Requests for superseded rules are skipped by workers and must not block new words.
            gap = min(
                timedelta(minutes=5),
                timedelta(seconds=deps.registry.manifest(cid).schedule.min_interval_seconds),
            )
            last_run = await s.scalar(
                select(ConnectorRun)
                .where(ConnectorRun.connector_id == cid)
                .order_by(ConnectorRun.started_at.desc(), ConnectorRun.id.desc())
                .limit(1)
            )
            if (
                latest is not None
                and latest.detail.get("project_id") == spec.project_id
                and latest.detail.get("rules_version") == spec.rules_version
                and now < latest.ts + gap
                and catalog.get(cid, {}).get("runnable") is True
                and (last_run is None or last_run.started_at < latest.ts)
            ):
                active = await s.scalar(
                    select(ConnectorRun)
                    .where(
                        ConnectorRun.connector_id == cid,
                        ConnectorRun.status.in_(ACTIVE_RUN),
                    )
                    .order_by(ConnectorRun.id.desc())
                    .limit(1)
                )
                results[cid] = ConnectorScanOut(
                    name=deps.registry.manifest(cid).name,
                    status="running",
                    next_allowed_at=latest.ts + gap if active is None else None,
                    run_id=active.id if active else None,
                    reason=None if active else "已有关键词扫描请求在排队，请稍后查看连接器运行情况",
                )
                continue

            async def enqueue(connector_id: str) -> None:
                await scan_keywords.kiq(connector_id, spec.model_dump(mode="json"))

            result = (
                await backfill.request(
                    s, deps.registry, [cid], catalog=catalog, enqueue=enqueue, now=now
                )
            )[cid]
            results[cid] = ConnectorScanOut(name=deps.registry.manifest(cid).name, **asdict(result))
            if result.status == "queued":
                await record(
                    s,
                    request,
                    user,
                    "rules.scan_queued",
                    target_type="connector",
                    target_id=cid,
                    detail=spec.model_dump(mode="json"),
                )
        await record(
            s,
            request,
            user,
            "rules.scan_requested",
            target_type="rules",
            target_id=spec.project_id,
            detail={
                **spec.model_dump(mode="json"),
                "connectors": {cid: r.status for cid, r in results.items()},
            },
        )
    return KeywordScanOut(scan=spec, connectors=results)
