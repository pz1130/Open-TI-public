"""Search stored article titles, summaries and matched excerpts."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from opti.api.deps import Principal, get_deps, require
from opti.api.pagination import page_offset, page_total
from opti.api.rbac import Perm
from opti.api.schemas import DocumentOut, DocumentPage
from opti.pipeline import documents

router = APIRouter(tags=["documents"])
Reader = Annotated[Principal, Depends(require(Perm.DOCUMENTS_READ))]


@router.get("/documents")
async def list_documents(
    request: Request,
    user: Reader,
    q: Annotated[str | None, Query(max_length=200)] = None,
    language: Annotated[str | None, Query(max_length=10)] = None,
    since: datetime | None = None,
    page: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> DocumentPage:
    deps = get_deps(request)
    async with deps.sessions() as session:
        total = await page_total(
            session, documents.search_statement(q, language, since), page, cursor
        )
        rows = await documents.search(
            session,
            q,
            language=language,
            since=since,
            cursor=cursor,
            limit=limit + 1,
            offset=page_offset(page, limit),
        )
    items = [
        DocumentOut(
            id=row.id,
            url=row.url,
            title=row.title,
            snippet=row.snippet,
            contexts=list(row.contexts),
            language=row.language,
            source_name=row.source_name,
            connectors=list(row.connectors),
            published_at=row.published_at,
            first_seen=row.first_seen,
            cluster_id=row.cluster_id,
        )
        for row in rows[:limit]
    ]
    return DocumentPage(
        total=total, items=items, next_cursor=items[-1].id if len(rows) > limit and items else None
    )
