"""Store only matched document excerpts and group near-duplicate reprints."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Select, delete, func, literal_column, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.core.documents import (
    MAX_CONTEXTS,
    NEAR_DUP_BITS,
    DocInput,
    build_search_text,
    fingerprint,
    from_signed64,
    hamming,
    simhash64,
    to_signed64,
)
from opti.core.normalize import normalize_text
from opti.db.models import Document

NEAR_SCAN_LIMIT = 5_000


def _body(doc: DocInput) -> str:
    return doc.text or f"{doc.title}\n{doc.summary}"


async def nearest_cluster(session: AsyncSession, simhash: int, now: datetime) -> int | None:
    rows = (
        await session.execute(
            select(Document.simhash, Document.cluster_id)
            .where(
                Document.first_seen
                >= now - timedelta(days=policy.current().scanning.document_near_days),
                Document.cluster_id.is_not(None),
            )
            .order_by(Document.id.desc())
            .limit(NEAR_SCAN_LIMIT)
        )
    ).all()
    best: tuple[int, int] | None = None
    for stored, cluster in rows:
        if cluster is None:
            continue
        distance = hamming(from_signed64(stored), simhash)
        if distance <= NEAR_DUP_BITS and (best is None or distance < best[0]):
            best = (distance, cluster)
    return best[1] if best is not None else None


async def upsert(
    session: AsyncSession, doc: DocInput, *, contexts: list[str], connector: str, now: datetime
) -> Document:
    body = _body(doc)
    content = fingerprint(body)
    if doc.url_normalized is not None:
        stmt = select(Document).where(Document.url_normalized == doc.url_normalized)
    else:
        stmt = select(Document).where(
            Document.url_normalized.is_(None), Document.content_sha256 == content
        )
    row = await session.scalar(stmt.order_by(Document.id).limit(1).with_for_update())
    if row is not None:
        row.connectors = sorted({*row.connectors, connector})
        row.contexts = list(dict.fromkeys([*row.contexts, *contexts]))[:MAX_CONTEXTS]
        row.title = row.title or doc.title
        row.snippet = row.snippet or doc.summary
        row.published_at = row.published_at or doc.published_at
        row.language = row.language or doc.language
        row.search_text = build_search_text(row.title, row.snippet, row.contexts)
        row.last_seen = now
        await session.flush()
        return row
    sh = simhash64(body)
    cluster = await nearest_cluster(session, sh, now)
    row = Document(
        url=doc.url,
        url_normalized=doc.url_normalized,
        title=doc.title,
        snippet=doc.summary,
        contexts=contexts[:MAX_CONTEXTS],
        search_text=build_search_text(doc.title, doc.summary, contexts),
        language=doc.language,
        source_name=doc.source_name,
        connectors=[connector],
        published_at=doc.published_at,
        content_sha256=content,
        simhash=to_signed64(sh),
        cluster_id=cluster,
        first_seen=now,
        last_seen=now,
    )
    session.add(row)
    await session.flush()
    if row.cluster_id is None:
        row.cluster_id = row.id
        await session.flush()
    return row


async def cluster_size(session: AsyncSession, cluster_id: int) -> int:
    return int(
        await session.scalar(
            select(func.count()).select_from(Document).where(Document.cluster_id == cluster_id)
        )
        or 0
    )


def brief(row: Document) -> dict[str, Any]:
    return {
        "id": row.id,
        "url": row.url,
        "title": row.title,
        "source_name": row.source_name,
        "language": row.language,
        "published_at": row.published_at.isoformat() if row.published_at else None,
    }


def _like(query: str) -> str:
    return "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search_statement(
    q: str | None, language: str | None = None, since: datetime | None = None
) -> Select[Document]:
    stmt = select(Document)
    query = normalize_text(q or "")
    if query:
        tsv = func.to_tsvector(literal_column("'simple'"), Document.search_text)
        stmt = stmt.where(
            or_(
                tsv.op("@@")(func.plainto_tsquery(literal_column("'simple'"), query)),
                Document.search_text.ilike(_like(query), escape="\\"),
            )
        )
    if language:
        stmt = stmt.where(Document.language == language)
    if since is not None:
        stmt = stmt.where(Document.first_seen >= since)
    return stmt


async def search(
    session: AsyncSession,
    q: str | None,
    *,
    language: str | None = None,
    since: datetime | None = None,
    cursor: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[Document]:
    stmt = search_statement(q, language, since)
    if cursor is not None:
        stmt = stmt.where(Document.id < cursor)
    return list(
        (await session.scalars(stmt.order_by(Document.id.desc()).offset(offset).limit(limit))).all()
    )


async def purge(session: AsyncSession, before: datetime) -> int:
    rows = await session.execute(
        delete(Document).where(Document.last_seen < before).returning(Document.id)
    )
    return len(rows.all())
