"""告警取证（设计文档 3.3 证据优先、11 证据链）：High/Critical 的域名告警自动截图并保存 HTML 快照。"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.db.models import Alert, AlertFinding, Entity, Evidence, Finding
from opti.pipeline.enrichment import EnrichmentService
from opti.storage.objects import ObjectStore
from opti.takedown.config import TakedownConfig
from opti.takedown.hosting import alert_host

log = logging.getLogger("opti.evidence")
EVIDENCE_ENRICHERS = ("screenshot",)
MAX_ATTEMPTS = 3


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


async def next_pending(session: AsyncSession, *, exclude: Sequence[int] = ()) -> Alert | None:
    stmt = (
        select(Alert)
        .where(
            Alert.evidence_status == "pending",
            Alert.status.in_(("open", "acknowledged")),
            Alert.ignored_at.is_(None),
        )
        .order_by(Alert.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if exclude:
        stmt = stmt.where(Alert.id.not_in(list(exclude)))
    return (await session.scalars(stmt)).first()


async def capture(
    session: AsyncSession,
    alert: Alert,
    enrichment: EnrichmentService,
    now: datetime,
    *,
    takedown: TakedownConfig | None = None,
) -> bool:
    finding = await session.scalar(
        select(Finding)
        .join(AlertFinding, AlertFinding.finding_id == Finding.id)
        .where(AlertFinding.alert_id == alert.id)
        .limit(1)
    )
    entity = await session.get(Entity, finding.entity_id) if finding is not None else None
    # 平台名单内的页面（linkedin.com、t.me 等）一律不让沙箱访问，证据只靠分析员上传
    if entity is not None and takedown is not None:
        url = alert.routing.get("url") if isinstance(alert.routing, dict) else None
        host = alert_host("url", url) if isinstance(url, str) else None
        host = host or alert_host(entity.type, entity.value)
        if takedown.platform_for(host) is not None:
            alert.evidence_status = "none"
            await session.flush()
            return False
    data: dict[str, Any] | None = None
    if finding is not None and entity is not None:
        url = alert.routing.get("url")
        targets = {"screenshot": ("url", url)} if isinstance(url, str) else None
        data = (
            await enrichment.enrich(entity, EVIDENCE_ENRICHERS, force=True, targets=targets)
        ).get(EVIDENCE_ENRICHERS[0])
    refs = [
        a for a in (data or {}).get("artifacts") or []
        if isinstance(a, dict) and a.get("key") and a.get("sha256")
    ]  # fmt: skip
    alert.evidence_attempts += 1
    if finding is None or not data or data.get("error") or not refs:
        reason = (data or {}).get("error") or "没有可保存的产物"
        log.warning("告警 %s 取证失败（第 %d 次）：%s", alert.id, alert.evidence_attempts, reason)
        if alert.evidence_attempts >= policy.current().scanning.evidence_attempts:
            alert.evidence_status = "failed"
        await session.flush()
        return False
    captured_at = _parse_time(data.get("captured_at")) or now
    for ref in refs:
        session.add(
            Evidence(
                finding_id=finding.id,
                alert_id=alert.id,
                kind=str(ref.get("name") or "artifact"),
                object_key=str(ref["key"]),
                sha256=str(ref["sha256"]),
                size=int(ref.get("size") or 0),
                content_type=str(ref.get("content_type") or "application/octet-stream"),
                version_id=ref.get("version_id"),
                captured_at=captured_at,
                node_id=str(ref.get("node_id") or "local"),
                method=str(data.get("method") or "unknown"),
                source_url=data.get("final_url"),
            )
        )
    alert.evidence_status = "done"
    await session.flush()
    return True


async def verify(session: AsyncSession, store: ObjectStore, evidence_id: int) -> bool:
    """重新下载证据并核对 SHA-256（证据链完整性检查）。"""
    ev = await session.get(Evidence, evidence_id)
    if ev is None:
        raise LookupError(f"证据 {evidence_id} 不存在")
    return hashlib.sha256(await store.get(ev.object_key)).hexdigest() == ev.sha256
