"""证据下载与上传（设计文档 11、14、4.2）：截图内联显示；HTML 快照只作为纯文本附件，绝不在平台域内渲染；分析员可上传截图。"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import EvidenceOut
from opti.core.uploads import MAX_UPLOAD_BYTES, UploadError, clean_image
from opti.db.models import Alert, AlertFinding, DomainObservation, Evidence, Finding, WatchedDomain
from opti.storage.artifacts import evidence_key
from opti.storage.objects import StoredObject

router = APIRouter(tags=["evidence"])
EvidenceReader = Annotated[Principal, Depends(require(Perm.EVIDENCE_READ))]
Uploader = Annotated[Principal, Depends(require(Perm.ALERTS_TRIAGE))]
MAX_UPLOADS_PER_ALERT = 20
# 图片解码与重编码占用 CPU 和数百 MB 内存：放到线程里执行，同时最多处理两张
_IMAGE_SLOTS = asyncio.Semaphore(2)
log = logging.getLogger("opti.evidence")


@router.get("/evidence/{evidence_id}/content", response_class=Response)
async def evidence_content(evidence_id: int, request: Request, user: EvidenceReader) -> Response:
    deps = get_deps(request)
    if deps.store is None:
        raise HTTPException(503, "object store not configured")
    async with deps.sessions.begin() as s:
        ev = await s.get(Evidence, evidence_id)
        project = None
        if ev is not None and ev.finding_id is not None:
            finding = await s.get(Finding, ev.finding_id)
            project = finding.project_id if finding else None
        elif ev is not None and ev.watch_observation_id is not None:
            observation = await s.get(DomainObservation, ev.watch_observation_id)
            watched = (
                await s.get(WatchedDomain, observation.watched_domain_id) if observation else None
            )
            project = watched.project_id if watched else None
        if ev is None or project != deps.rules.project:
            raise HTTPException(404, "evidence not found")
        await record(
            s,
            request,
            user,
            "evidence.download",
            target_type="evidence",
            target_id=ev.id,
            detail={"kind": ev.kind, "sha256": ev.sha256},
        )
    data = await deps.store.get(ev.object_key)
    if hashlib.sha256(data).hexdigest() != ev.sha256:
        raise HTTPException(409, "evidence integrity check failed")
    headers = {
        "X-Content-SHA256": ev.sha256,
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "Cache-Control": "private, no-store",
    }
    if ev.content_type == "image/png":
        headers["Content-Disposition"] = f'inline; filename="evidence-{ev.id}.png"'
        return Response(data, media_type="image/png", headers=headers)
    ext = ev.content_type.split("/")[-1].split(";")[0] or "bin"
    headers["Content-Disposition"] = f'attachment; filename="evidence-{ev.id}.{ext}.txt"'
    return Response(data, media_type="text/plain; charset=utf-8", headers=headers)


async def _body(request: Request) -> bytes:
    """流式读取请求体，超过上限立即中止，不把超大请求读进内存。"""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "screenshot is larger than 10 MB")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "screenshot is larger than 10 MB")
        chunks.append(chunk)
    return b"".join(chunks)


async def _alert_finding(
    s: Any, alert_id: int, project: str, *, lock: bool = False
) -> tuple[Alert, Finding]:
    stmt = (
        select(Alert, Finding)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .where(Alert.id == alert_id, Alert.project_id == project)
        .limit(1)
    )
    if lock:
        stmt = stmt.with_for_update(of=Alert)  # 同一告警的并发上传按顺序检查数量上限
    row = (await s.execute(stmt)).first()
    if row is None:
        raise HTTPException(404, "alert not found")
    if row[0].status == "superseded":  # 与研判一致：被取代的告警只读，截图应传到新告警
        raise HTTPException(409, "alert superseded by a newer alert")
    return row[0], row[1]


async def _discard(request: Request, stored: StoredObject) -> None:
    """数据库没记下这次上传：对象按内容寻址，没有任何证据引用时才删除。"""
    deps = get_deps(request)
    async with deps.sessions() as s:
        used = await s.scalar(select(Evidence.id).where(Evidence.object_key == stored.key).limit(1))
    if used is None and deps.store is not None:
        await deps.store.delete(stored.key, stored.version_id)


@router.post("/alerts/{alert_id}/evidence", status_code=201)
async def upload_evidence(alert_id: int, request: Request, user: Uploader) -> EvidenceOut:
    deps = get_deps(request)
    if deps.store is None:
        raise HTTPException(503, "object store not configured")
    async with deps.sessions() as s:
        await _alert_finding(s, alert_id, deps.rules.project)
    body = await _body(request)
    try:
        async with _IMAGE_SLOTS:
            image = await asyncio.to_thread(
                clean_image, body, request.headers.get("content-type", "")
            )
    except UploadError as e:
        raise HTTPException(e.status, str(e)) from e
    sha = hashlib.sha256(image.data).hexdigest()
    stored = await deps.store.put(evidence_key(sha, "image/png"), image.data, "image/png")
    now: datetime = deps.clock()
    try:
        async with deps.sessions.begin() as s:
            alert, finding = await _alert_finding(s, alert_id, deps.rules.project, lock=True)
            count = await s.scalar(
                select(func.count())
                .select_from(Evidence)
                .where(Evidence.alert_id == alert.id, Evidence.kind == "upload")
            )
            if (count or 0) >= MAX_UPLOADS_PER_ALERT:
                raise HTTPException(409, "too many uploaded screenshots for this alert")
            url = alert.routing.get("url") if isinstance(alert.routing, dict) else None
            ev = Evidence(
                finding_id=finding.id,
                alert_id=alert.id,
                kind="upload",
                object_key=stored.key,
                sha256=stored.sha256,
                size=stored.size,
                content_type="image/png",
                version_id=stored.version_id,
                captured_at=now,
                node_id="upload",
                method="analyst-upload",
                source_url=url if isinstance(url, str) else None,
                uploaded_by=user.user_id,
                original_sha256=image.original_sha256,
            )
            s.add(ev)
            await s.flush()
            await record(
                s,
                request,
                user,
                "evidence.upload",
                target_type="evidence",
                target_id=ev.id,
                detail={
                    "alert_id": alert.id,
                    "sha256": stored.sha256,
                    "original_sha256": image.original_sha256,
                    "size": stored.size,
                },
            )
    except BaseException:
        try:
            await _discard(request, stored)
        except Exception as e:  # 清理失败只记日志，不能掩盖原来的错误（例如 409）
            log.warning("上传失败后清理对象 %s 失败：%s", stored.key, type(e).__name__)
        raise
    return EvidenceOut(
        id=ev.id,
        kind=ev.kind,
        content_type=ev.content_type,
        sha256=ev.sha256,
        size=ev.size,
        captured_at=ev.captured_at,
        node_id=ev.node_id,
        method=ev.method,
        source_url=ev.source_url,
        uploaded_by=user.username,
        original_sha256=ev.original_sha256,
    )
