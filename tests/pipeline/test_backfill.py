from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import ConnectorRun
from opti.pipeline import backfill
from opti.pipeline.backfill import BackfillResult
from opti.sdk.registry import Registry

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)
READY = {"crtsh": {"runnable": True}, "dnstwist": {"runnable": True}}


def _run(cid: str, status: str, started: datetime) -> ConnectorRun:
    return ConnectorRun(
        connector_id=cid, started_at=started, status=status, items=0, errors=0, message=""
    )


async def _request(
    session: AsyncSession, catalog: dict[str, Any], fail: bool = False
) -> tuple[dict[str, BackfillResult], list[str]]:
    queued: list[str] = []

    async def enqueue(cid: str) -> None:
        if fail:
            raise ConnectionError("broker down")
        queued.append(cid)

    out = await backfill.request(
        session, Registry(), ("crtsh", "dnstwist"), catalog=catalog, enqueue=enqueue, now=NOW
    )
    return out, queued


async def test_queues_when_never_run(session: AsyncSession) -> None:
    out, queued = await _request(session, READY)
    assert out == {"crtsh": BackfillResult("queued"), "dnstwist": BackfillResult("queued")}
    assert queued == ["crtsh", "dnstwist"]


async def test_unavailable_when_not_runnable(session: AsyncSession) -> None:
    catalog = {"crtsh": {"runnable": False, "reason": "license_not_approved：法务尚未批准"}}
    out, queued = await _request(session, catalog)
    assert out["crtsh"] == BackfillResult(
        "unavailable", reason="license_not_approved：法务尚未批准"
    )
    assert out["dnstwist"] == BackfillResult("unavailable", reason="unknown_connector")
    assert queued == []


async def test_running_and_too_soon(session: AsyncSession) -> None:
    running = _run("crtsh", "dispatched", NOW - timedelta(minutes=5))
    recent = _run("dnstwist", "ok", NOW - timedelta(hours=3))
    session.add_all([running, recent])
    await session.flush()
    out, queued = await _request(session, READY)
    assert out["crtsh"] == BackfillResult("running", run_id=running.id)
    # dnstwist 最小间隔 12 小时
    assert out["dnstwist"] == BackfillResult(
        "too_soon", next_allowed_at=NOW - timedelta(hours=3) + timedelta(hours=12)
    )
    assert queued == []


async def test_queues_after_min_interval(session: AsyncSession) -> None:
    session.add(_run("crtsh", "error", NOW - timedelta(hours=1, seconds=1)))
    await session.flush()
    out, queued = await _request(session, READY)
    assert out["crtsh"].status == "queued" and "crtsh" in queued


async def test_queue_error_is_reported(session: AsyncSession) -> None:
    out, _ = await _request(session, READY, fail=True)
    assert out["crtsh"] == BackfillResult("unavailable", reason="queue_error")


def test_triggers_by_kind() -> None:
    assert backfill.TRIGGERS["brand"] == ("crtsh", "dnstwist")
    assert backfill.TRIGGERS["restricted"] == ("crtsh",)
    assert backfill.TRIGGERS["official"] == ("dnstwist",)
    assert backfill.TRIGGERS["lookalike"] == ()


async def test_any_active_run_prevents_a_new_backfill(session: AsyncSession) -> None:
    active = _run("crtsh", "running", NOW - timedelta(hours=3))
    session.add_all([active, _run("crtsh", "error", NOW - timedelta(hours=2))])
    await session.flush()
    out, queued = await _request(session, READY)
    assert out["crtsh"] == BackfillResult("running", run_id=active.id)
    assert "crtsh" not in queued
