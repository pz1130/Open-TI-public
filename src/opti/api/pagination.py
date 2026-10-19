"""Numbered pages alongside the existing cursor API."""

from typing import Any

from fastapi import HTTPException
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def page_total(
    session: AsyncSession, stmt: Select[Any], page: int | None, cursor: int | None
) -> int:
    if page is not None and cursor is not None:
        raise HTTPException(422, "page and cursor cannot be combined")
    return int(
        await session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    )


def page_offset(page: int | None, limit: int) -> int:
    return ((page or 1) - 1) * limit
