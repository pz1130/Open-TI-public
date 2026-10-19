"""托管信息预取（设计文档 12.1）：worker 为高危告警查询主机的 DNS / RDAP 与托管 IP 的 RDAP，
接口进程只读缓存，不对外发请求。"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db import repo
from opti.db.models import Alert, AlertFinding, Entity, Finding
from opti.pipeline.enrichment import EnrichmentService

TAKEDOWN_ENRICHERS = ("ip_rdap",)
HOST_ENRICHERS = ("dns", "rdap")
MAX_IPS = 3
PENDING_SEVERITIES = ("critical", "high")
PENDING_WINDOW = timedelta(days=30)
MANUAL_SOURCE = "manual_submission"  # 与 opti.pipeline.submissions.CONNECTOR_ID 一致（避免循环导入，有测试保证）


@dataclass(frozen=True)
class HostData:
    host: str
    rdap: dict[str, Any] | None
    dns: dict[str, Any] | None
    ips: dict[str, dict[str, Any] | None]  # IP → ip_rdap 结果；None 表示还没查到


def alert_host(entity_type: str, value: str) -> str | None:
    if entity_type == "domain":
        return value
    if entity_type == "url":
        try:
            return urlsplit(value).hostname
        except ValueError:
            return None
    return None


def ip_literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


def host_ips(dns: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("a", "aaaa"):
        raw = dns.get(key)
        if isinstance(raw, list):
            values.extend(
                ip
                for v in sorted(x for x in raw if isinstance(x, str))
                if isinstance(v, str) and (ip := ip_literal(v))
            )
    return list(dict.fromkeys(values))[:MAX_IPS]


def _cached(entity: Entity | None, eid: str) -> dict[str, Any] | None:
    entry = (entity.enrichment or {}).get(eid) if entity is not None else None
    data = entry.get("data") if isinstance(entry, dict) else None
    return dict(data) if isinstance(data, dict) else None


async def _host_entity(session: AsyncSession, entity: Entity, host: str, now: datetime) -> Entity:
    if entity.type == "domain":
        return entity
    return await repo.upsert_entity(session, "domain", host, now)


async def prefetch(
    session: AsyncSession, enrichment: EnrichmentService, entity: Entity, now: datetime
) -> list[str]:
    """查询主机的 DNS 与 RDAP、托管 IP 的 RDAP（都有缓存，重复调用不重复请求）。返回已查询的 IP。"""
    host = alert_host(entity.type, entity.value)
    if host is None:
        return []
    literal = ip_literal(host)
    if literal is not None:
        ips = [literal]
    else:
        dom = await _host_entity(session, entity, host, now)
        ips = host_ips((await enrichment.enrich(dom, HOST_ENRICHERS)).get("dns") or {})
    for ip in ips:
        await enrichment.enrich(
            await repo.upsert_entity(session, "ip", ip, now), TAKEDOWN_ENRICHERS
        )
    await session.flush()
    return ips


async def load_host_data(session: AsyncSession, entity: Entity) -> HostData:
    """只读缓存，供接口生成投诉对象清单。"""
    return (await load_host_data_many(session, [entity]))[entity.id]


async def load_host_data_many(
    session: AsyncSession, entities: Sequence[Entity]
) -> dict[int, HostData]:
    """批量只读缓存：每个实体的结果与 load_host_data 相同，固定两次查询（URL 主机的域名实体、全部 IP 实体）。"""
    hosts = {e.id: alert_host(e.type, e.value) or e.value for e in entities}
    lookup = {
        hosts[e.id] for e in entities if e.type != "domain" and ip_literal(hosts[e.id]) is None
    }
    domains = (
        {
            d.value: d
            for d in await session.scalars(
                select(Entity).where(Entity.type == "domain", Entity.value.in_(lookup))
            )
        }
        if lookup
        else {}
    )
    parts: dict[int, tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]] = {}
    for e in entities:
        literal = ip_literal(hosts[e.id])
        if literal is not None:
            parts[e.id] = (None, None, [literal])
        else:
            dom = e if e.type == "domain" else domains.get(hosts[e.id])
            dns = _cached(dom, "dns")
            parts[e.id] = (_cached(dom, "rdap"), dns, host_ips(dns or {}))
    wanted = {ip for _, _, ips in parts.values() for ip in ips}
    rows = (
        {
            r.value: r
            for r in await session.scalars(
                select(Entity).where(Entity.type == "ip", Entity.value.in_(wanted))
            )
        }
        if wanted
        else {}
    )
    return {
        eid: HostData(hosts[eid], rdap, dns, {ip: _cached(rows.get(ip), "ip_rdap") for ip in ips})
        for eid, (rdap, dns, ips) in parts.items()
    }


async def pending_entity_ids(session: AsyncSession, now: datetime, *, limit: int) -> list[int]:
    """近 30 天未关闭的高危告警、以及非平台的人工提交对应的实体，新告警优先；平台链接不查。"""
    stmt = (
        select(Finding.entity_id)
        .join(AlertFinding, AlertFinding.finding_id == Finding.id)
        .join(Alert, Alert.id == AlertFinding.alert_id)
        .where(
            Alert.status.in_(("open", "acknowledged")),
            or_(Alert.severity.in_(PENDING_SEVERITIES), Finding.sources.contains([MANUAL_SOURCE])),
            Finding.match["platform"].astext.is_(None),
            Alert.created_at > now - PENDING_WINDOW,
        )
        .group_by(Finding.entity_id)
        .order_by(func.max(Alert.id).desc())
        .limit(limit)
    )
    return list((await session.scalars(stmt)).all())
