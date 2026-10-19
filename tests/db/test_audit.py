from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db import audit

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


async def test_chain_links_records(session: AsyncSession) -> None:
    a = await audit.append(session, actor="alice", action="auth.login", now=NOW, ip="10.1.2.3")
    b = await audit.append(
        session, actor="alice", action="alert.update", now=NOW + timedelta(seconds=1),
        target_type="alert", target_id="7", detail={"before": "open", "after": "closed"},
    )  # fmt: skip
    assert a.prev_hash == audit.GENESIS and b.prev_hash == a.hash and len(b.hash) == 64
    assert await audit.verify_chain(session) is None


async def test_non_utc_time_is_normalized(session: AsyncSession) -> None:
    shanghai = timezone(timedelta(hours=8))
    await audit.append(session, actor="alice", action="auth.login", now=NOW.astimezone(shanghai))
    assert await audit.verify_chain(session) is None


async def test_audit_log_is_append_only(session: AsyncSession) -> None:
    row = await audit.append(session, actor="alice", action="auth.login", now=NOW)
    # 出错的语句必须在保存点内执行，异常穿出保存点后才回滚到保存点，外层事务仍可继续使用
    with pytest.raises(DBAPIError, match="只允许追加"):
        async with session.begin_nested():
            await session.execute(
                text("UPDATE audit_log SET actor = 'mallory' WHERE id = :i"), {"i": row.id}
            )
    with pytest.raises(DBAPIError, match="只允许追加"):
        async with session.begin_nested():
            await session.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": row.id})


async def test_verify_detects_tampering(session: AsyncSession) -> None:
    await audit.append(session, actor="alice", action="auth.login", now=NOW)
    second = await audit.append(session, actor="alice", action="alert.view", now=NOW, target_id="1")
    await audit.append(session, actor="alice", action="auth.logout", now=NOW)
    # 绕过触发器模拟数据库层面的篡改（测试容器中是超级用户）
    await session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    await session.execute(
        text("UPDATE audit_log SET actor = 'mallory' WHERE id = :i"), {"i": second.id}
    )
    await session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    session.expire_all()
    assert await audit.verify_chain(session) == second.id


async def test_concurrent_appends_do_not_fork(clean_db: str) -> None:
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(clean_db)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def write(i: int) -> None:
        async with sessions.begin() as s:
            await audit.append(s, actor=f"actor-{i}", action="concurrent", now=NOW)

    try:
        await asyncio.gather(*(write(i) for i in range(8)))
        async with sessions() as s:
            assert await audit.verify_chain(s, batch=2) is None
            assert await s.scalar(text("SELECT count(*) FROM audit_log")) == 8
    finally:
        await engine.dispose()
