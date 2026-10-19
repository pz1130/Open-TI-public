from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.configs import revisions

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 12, tzinfo=UTC)


async def test_append_increments_and_checks_base(session: AsyncSession) -> None:
    first = await revisions.append(
        session, "rules", "a", base_version=0, user="alice", note=None, now=NOW
    )
    second = await revisions.append(
        session, "rules", "b", base_version=1, user="bob", note="n", now=NOW
    )
    assert (first.version, second.version) == (1, 2)
    with pytest.raises(revisions.VersionConflict) as e:
        await revisions.append(
            session, "rules", "c", base_version=1, user="carol", note=None, now=NOW
        )
    assert e.value.current == 2
    assert (await revisions.heads(session))["rules"] == revisions.Head(2, second.digest)
    assert [r.version for r in await revisions.history(session, "rules")] == [2, 1]
    assert (await revisions.get(session, "rules", 1)).content == "a"  # type: ignore[union-attr]
    assert "organization" not in await revisions.heads(session)


async def test_restored_from_is_kept(session: AsyncSession) -> None:
    await revisions.append(
        session, "organization", "name: a\n", base_version=0, user="u", note=None, now=NOW
    )
    row = await revisions.append(
        session,
        "organization",
        "name: a\n",
        base_version=1,
        user="u",
        note="恢复 v1",
        now=NOW,
        restored_from=1,
    )
    assert row.restored_from == 1


async def test_report_status_upserts(session: AsyncSession) -> None:
    await revisions.report_status(
        session, process="api@h", kind="rules", version=0, digest="d", error=None, now=NOW
    )
    await revisions.report_status(
        session, process="api@h", kind="rules", version=3, digest="e", error="bad", now=NOW
    )
    rows = await revisions.statuses(session)
    assert [(r.process, r.version, r.error) for r in rows] == [("api@h", 3, "bad")]
