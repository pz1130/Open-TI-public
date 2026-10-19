"""Persist ransomware aggregator posts and rematch recent history."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.leakposts import MAX_LINKS, Post
from opti.db.models import LeakPost

if TYPE_CHECKING:
    from opti.pipeline.processor import Processor

REMATCH_DAYS = 365


async def upsert_post(session: AsyncSession, post: Post, now: datetime) -> LeakPost:
    stmt = (
        pg_insert(LeakPost)
        .values(
            key=post.key,
            group_name=post.group,
            victim=post.victim,
            domain=post.domain,
            country=post.country,
            activity=post.activity,
            discovered=post.discovered,
            published=post.published,
            sources=[post.source],
            links=list(post.links),
            other_links=list(post.other_links),
            description=post.description,
            first_seen=now,
            last_seen=now,
        )
        .on_conflict_do_nothing(index_elements=["key"])
    )
    await session.execute(stmt)
    row = await session.scalar(select(LeakPost).where(LeakPost.key == post.key).with_for_update())
    assert row is not None
    row.sources = sorted({*row.sources, post.source})
    row.links = list(dict.fromkeys([*row.links, *post.links]))[:MAX_LINKS]
    row.other_links = list(dict.fromkeys([*row.other_links, *post.other_links]))[:MAX_LINKS]
    row.discovered = min(row.discovered, post.discovered)
    row.domain = row.domain or post.domain
    row.country = row.country or post.country
    row.activity = row.activity or post.activity
    row.description = row.description or post.description
    row.last_seen = now
    return row


def public_post(row: LeakPost) -> dict[str, Any]:
    return {
        "group": row.group_name,
        "victim": row.victim,
        "domain": row.domain,
        "country": row.country,
        "activity": row.activity,
        "discovered": row.discovered.isoformat(),
        "published": row.published.isoformat() if row.published else None,
        "sources": list(row.sources),
        "links": list(row.links),
        "other_links": list(row.other_links),
        "description": row.description,
    }


async def rematch(
    session: AsyncSession, processor: Processor, *, now: datetime, days: int = REMATCH_DAYS
) -> list[int]:
    rows = (
        await session.scalars(
            select(LeakPost).where(LeakPost.discovered >= now - timedelta(days=days))
        )
    ).all()
    alerts: list[int] = []
    for row in rows:
        alerts += await processor.rematch_post(session, row, now)
    return alerts
