"""Watcher 对照的数据库查询：本平台同期发现的仿冒域名与钓鱼主机。"""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.domains import normalize_domain, parse_domain
from opti.db.models import Entity, Finding

WATCH_CATEGORIES = ("typosquat_domain", "phishing_site")


def _host(entity_type: str, value: str) -> str | None:
    if entity_type == "url":
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None
    return normalize_domain(value) if value else None


async def our_hosts(
    session: AsyncSession, project: str, *, since: datetime, until: datetime
) -> set[str]:
    rows = await session.execute(
        select(Entity.type, Entity.value)
        .join(Finding, Finding.entity_id == Entity.id)
        .where(
            Finding.project_id == project,
            Finding.category.in_(WATCH_CATEGORIES),
            Finding.first_seen >= since,
            Finding.first_seen < until,
            Entity.type.in_(("domain", "url")),
        )
    )
    return {h for t, v in rows.all() if (h := _host(t, v))}


async def known_hosts(session: AsyncSession, project: str, hosts: Collection[str]) -> set[str]:
    """这些主机是否在任何时间被本平台发现过（用于区分"漏报"与"不在对照时段内"）。"""
    if not hosts:
        return set()
    rows = await session.execute(
        select(Entity.type, Entity.value)
        .join(Finding, Finding.entity_id == Entity.id)
        .where(Finding.project_id == project, Entity.type.in_(("domain", "url")))
    )

    def registered(host: str) -> str:
        parts = parse_domain(host)
        return parts.registered if parts else host

    known = {registered(h) for kind, value in rows if (h := _host(kind, value))}
    return {h for h in hosts if registered(h) in known}
