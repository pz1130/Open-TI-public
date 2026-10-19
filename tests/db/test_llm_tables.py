from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import LlmProvider, LlmSettings

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 10, tzinfo=UTC)


def _provider(name: str) -> LlmProvider:
    return LlmProvider(
        name=name, preset="selfhosted", base_url="http://vllm:8000/v1", model="qwen",
        json_mode=True, temperature=0.0, timeout_seconds=60, created_at=NOW, updated_at=NOW,
    )  # fmt: skip


def _settings(**kw: object) -> LlmSettings:
    base: dict[str, object] = dict(
        id=1, enabled=False, gray_zone_low=30, gray_zone_high=70, max_per_run=20,
        max_attempts=3, max_wait_minutes=30, summary_language="Chinese", updated_at=NOW,
    )  # fmt: skip
    base.update(kw)
    return LlmSettings(**base)


async def test_provider_round_trip_and_unique_name(session: AsyncSession) -> None:
    p = _provider("Local")
    p.api_key_enc, p.api_key_hint = b"v1" + bytes(40), "WXYZ"
    session.add(p)
    await session.flush()
    got = await session.scalar(select(LlmProvider).where(LlmProvider.name == "Local"))
    assert got is not None and bytes(got.api_key_enc or b"")[:2] == b"v1" and got.temperature == 0.0
    session.add(_provider("Local"))
    with pytest.raises(IntegrityError):
        await session.flush()


@pytest.mark.parametrize(
    "bad",
    [{"id": 2}, {"gray_zone_low": 80, "gray_zone_high": 20}, {"gray_zone_high": 101}],
)
async def test_settings_checks(session: AsyncSession, bad: dict[str, object]) -> None:
    session.add(_settings(**bad))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_settings_restrict_delete_and_distinct(session: AsyncSession) -> None:
    a, b = _provider("A"), _provider("B")
    session.add_all([a, b])
    await session.flush()
    session.add(_settings(primary_id=a.id, backup_id=a.id))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_in_use_provider_cannot_be_deleted(session: AsyncSession) -> None:
    a = _provider("A")
    session.add(a)
    await session.flush()
    session.add(_settings(primary_id=a.id))
    await session.flush()
    await session.delete(a)
    with pytest.raises(IntegrityError):
        await session.flush()
