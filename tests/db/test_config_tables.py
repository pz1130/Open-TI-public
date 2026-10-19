from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import ConfigRevision, ConfigRuntimeStatus, ConfigSecret

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _rev(kind: str = "rules", version: int = 1) -> ConfigRevision:
    return ConfigRevision(
        kind=kind, version=version, content="x", digest="d", created_by="alice", created_at=NOW
    )


async def test_version_is_unique_per_kind(session: AsyncSession) -> None:
    session.add_all([_rev("rules", 1), _rev("organization", 1)])
    await session.flush()
    session.add(_rev("rules", 1))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_kind_is_constrained(session: AsyncSession) -> None:
    session.add(_rev("not-a-kind", 1))
    with pytest.raises(IntegrityError):
        await session.flush()


@pytest.mark.parametrize(
    "kind",
    (
        "retention",
        "campaigns",
        "takedown",
        "takedown_templates",
        "tickets",
        "vendors",
        "software",
        "sharing",
        "connectors",
    ),
)
async def test_phase3_revision_kinds_are_allowed(session: AsyncSession, kind: str) -> None:
    session.add(_rev(kind))
    await session.flush()


async def test_phase3_secret_kinds_are_limited(session: AsyncSession) -> None:
    for kind in ("tickets", "sharing", "connectors"):
        session.add(
            ConfigSecret(
                kind=kind, name="x", value_enc=None, hint=None, updated_by="u", updated_at=NOW
            )
        )
    await session.flush()
    session.add(
        ConfigSecret(
            kind="retention", name="x", value_enc=None, hint=None, updated_by="u", updated_at=NOW
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_version_starts_at_one(session: AsyncSession) -> None:
    session.add(_rev("rules", 0))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_status_key_is_process_and_kind(session: AsyncSession) -> None:
    session.add(
        ConfigRuntimeStatus(process="api@h", kind="rules", version=0, digest="d", updated_at=NOW)
    )
    session.add(
        ConfigRuntimeStatus(
            process="api@h", kind="organization", version=0, digest="d", updated_at=NOW
        )
    )
    await session.flush()
    session.add(
        ConfigRuntimeStatus(process="api@h", kind="rules", version=1, digest="e", updated_at=NOW)
    )
    with pytest.raises(IntegrityError):
        await session.flush()
