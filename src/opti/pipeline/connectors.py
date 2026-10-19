"""连接器中心（设计文档 5.4、14）：清单 + 实例配置 + 准入结果 + 运行记录 → 只读目录与健康状态。

平台进程按自己的环境变量检查本地运行的连接器；remote 模式下境外连接器以采集节点心跳上报的结果为准。
凭据只给出"是否已设置"，不含值。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import CollectorNode, ConnectorRun
from opti.sdk.context import SecretProvider
from opti.sdk.manifest import ManifestError
from opti.sdk.registry import InstanceConfig, Registry, load_instance_config, readiness

STALE_AFTER = timedelta(hours=48)
WAITING = "waiting_for_node：等待采集节点上报"
_HTTP_STATUS = re.compile(r"HttpError: [1-5][0-9]{2}\Z")
_REASONS = {
    "ok": "ok",
    "disabled": "disabled：实例未启用",
    "license_not_approved": "license_not_approved：法务尚未批准",
    "darkweb_not_approved": "darkweb_not_approved：暗网数据源尚未批准",
    "unknown_plan": "unknown_plan：套餐未定义",
    "unconfigured": "unconfigured：缺少凭据",
    "config_invalid": "config_invalid：实例配置不合法",
}


def _public_message(message: str) -> str:
    """运行异常可能带 URL 或凭据，只公开固定格式的 HTTP 状态码。"""
    return message if _HTTP_STATUS.fullmatch(message) else ""


def _public_reason(reason: Any) -> str:
    code = str(reason or "").split("：", 1)[0].split(":", 1)[0]
    return _REASONS.get(code, "unavailable：准入状态不可用")


def health(
    kind: Sequence[str],
    *,
    runnable: bool | None,
    reason: str = "",
    last_status: str | None,
    last_ok: datetime | None,
    stream: str | None,
    now: datetime,
) -> str:
    if "enricher" in kind:
        return "n/a"
    if runnable is None:
        return "unknown"
    if not runnable:
        return "disabled" if reason.startswith("disabled") else "blocked"
    if stream is not None:
        return "ok" if stream == "running" else "failing"
    if last_status is None:
        return "never"
    if last_status == "error":
        return "failing"
    if last_status in ("running", "dispatched"):
        return "ok"
    if last_ok is None or now - last_ok > STALE_AFTER:
        return "stale"
    return "ok"


def _instance(config_dir: Path, connector_id: str) -> InstanceConfig:
    try:
        return load_instance_config(config_dir, connector_id)
    except ManifestError:
        return InstanceConfig()  # 配置不合法时 readiness() 已给出原因


async def _runs(
    session: AsyncSession, now: datetime
) -> tuple[dict[str, ConnectorRun], dict[str, datetime | None], dict[str, tuple[int, int]]]:
    latest_ids = select(func.max(ConnectorRun.id)).group_by(ConnectorRun.connector_id)
    latest = {
        r.connector_id: r
        for r in await session.scalars(select(ConnectorRun).where(ConnectorRun.id.in_(latest_ids)))
    }
    last_ok = {
        str(cid): ended
        for cid, ended in (
            await session.execute(
                select(ConnectorRun.connector_id, func.max(ConnectorRun.ended_at))
                .where(ConnectorRun.status == "ok")
                .group_by(ConnectorRun.connector_id)
            )
        ).all()
    }
    day = {
        str(cid): (int(n), int(e or 0))
        for cid, n, e in (
            await session.execute(
                select(
                    ConnectorRun.connector_id,
                    func.count(),
                    func.count().filter(ConnectorRun.status == "error"),
                )
                .where(ConnectorRun.started_at >= now - timedelta(hours=24))
                .group_by(ConnectorRun.connector_id)
            )
        ).all()
    }
    return latest, last_ok, day


async def catalog(
    session: AsyncSession,
    registry: Registry,
    config_dir: Path,
    secrets: SecretProvider,
    *,
    remote: bool,
    now: datetime,
) -> list[dict[str, Any]]:
    local = readiness(registry, config_dir, secrets)
    reports: dict[str, tuple[str, dict[str, Any]]] = {}
    streams: dict[str, str] = {}
    for node in await session.scalars(
        select(CollectorNode).order_by(CollectorNode.last_seen.desc())
    ):
        status = node.status if isinstance(node.status, dict) else {}
        for cid, info in (status.get("connectors") or {}).items():
            if isinstance(info, dict):
                reports.setdefault(str(cid), (node.node_id, info))  # 以最近一次心跳的节点为准
        for cid, state in (status.get("streams") or {}).items():
            streams.setdefault(str(cid), str(state))
    latest, last_ok, day = await _runs(session, now)
    out: list[dict[str, Any]] = []
    for m in registry.manifests():
        inst = _instance(config_dir, m.id)
        on_node = remote and m.egress == "overseas"
        report = reports.get(m.id) if on_node else None
        ready: dict[str, Any] | None = (report[1] if report else None) if on_node else local[m.id]
        runnable = ready.get("runnable") if ready is not None else None
        runnable = runnable if isinstance(runnable, bool) else None
        creds = ready.get("credentials") if ready is not None else None
        creds = creds if isinstance(creds, dict) else {}
        run = latest.get(m.id)
        runs_24h, errors_24h = day.get(m.id, (0, 0))
        out.append({
            "id": m.id, "name": m.name, "category": m.category, "tier": m.tier.value, "kind": list(m.kind),
            "egress": m.egress, "homepage": m.homepage, "tos_url": m.tos_url, "commercial_use": m.commercial_use,
            "last_reviewed": m.last_reviewed, "pii_risk": m.pii_risk, "compliance_notes": m.compliance_notes,
            "schedule": m.schedule.default, "enabled": inst.enabled, "license_approved": inst.license_approved,
            "license_ref": inst.license_ref, "plan": inst.plan, "runnable": runnable,
            "reason": _public_reason(ready.get("reason")) if ready is not None else WAITING,
            "location": f"node:{report[0]}" if report else ("collector" if on_node else "platform"),
            "credentials": [
                {"name": c.name, "required": c.required,
                 "configured": bool(creds[c.name]) if c.name in creds else None}
                for c in m.credentials
            ],
            "health": health(
                m.kind, runnable=runnable, reason=str(ready.get("reason", "")) if ready else "",
                last_status=run.status if run else None, last_ok=last_ok.get(m.id),
                stream=streams.get(m.id) if "stream" in m.kind else None, now=now,
            ),
            "last_run": None if run is None else {
                "started_at": run.started_at, "ended_at": run.ended_at, "status": run.status, "items": run.items,
                "errors": run.errors, "message": _public_message(run.message), "node_id": run.node_id,
            },
            "last_success_at": last_ok.get(m.id), "runs_24h": runs_24h, "errors_24h": errors_24h,
        })  # fmt: skip
    return out
