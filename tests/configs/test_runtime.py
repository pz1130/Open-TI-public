import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from redis.asyncio import Redis
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti import organization as org_mod
from opti.configs import kinds, revisions
from opti.configs.runtime import (
    EDGE_RULES_KEY,
    HEARTBEAT_SECONDS,
    ConfigRuntime,
    ConfigSnapshot,
    RedisRulePublisher,
)
from opti.configs.testing import FakeKV
from opti.core.config import ProjectRules
from opti.db.engine import make_sessionmaker
from opti.db.models import ConfigRevision
from opti.settings import Settings

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 12, tzinfo=UTC)


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()
    org_mod.set_current(None)


@pytest.fixture
def settings(clean_db: str, sbr_rules_path: Path, tmp_path: Path) -> Settings:
    org = tmp_path / "organization.yaml"
    org.write_text("name: File Org\n", encoding="utf-8")
    return Settings(database_url=clean_db, rules_path=sbr_rules_path, organization_path=org)


def _renamed(rules: ProjectRules, project: str) -> str:
    data = kinds.to_data("rules", rules)
    data["project"] = project
    return kinds.from_data("rules", data)


async def _save(
    sessions: async_sessionmaker[AsyncSession], kind: str, text: str, base: int
) -> None:
    async with sessions.begin() as s:
        await revisions.append(s, kind, text, base_version=base, user="t", note=None, now=NOW)


async def test_start_uses_files_when_db_has_no_revisions(sessions, settings, sbr_rules) -> None:
    rt = await ConfigRuntime.start(settings, sessions, process="api@t")
    assert rt.snapshot.rules == sbr_rules and rt.snapshot.rules_version == 0
    assert rt.snapshot.organization.name == "File Org"
    assert org_mod.current_organization().name == "File Org"
    async with sessions() as s:
        rows = await revisions.statuses(s)
    assert {(r.process, r.kind, r.version) for r in rows} == {
        ("api@t", kind, 0) for kind in kinds.KINDS
    }


async def test_web_identity_survives_invalid_old_oidc_file(sessions, settings, tmp_path) -> None:
    from dataclasses import replace

    await _save(sessions, "identity", kinds.from_data("identity", {"label": "Web login"}), 0)
    broken = tmp_path / "oidc.yaml"
    broken.write_text("enabled: [broken YAML\n")
    rt = await ConfigRuntime.start(replace(settings, oidc_config=broken), sessions)
    assert rt.snapshot.identity.label == "Web login"


async def test_refresh_swaps_snapshot_and_notifies(sessions, settings, sbr_rules) -> None:
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t")
    seen: list[tuple[str, str]] = []
    rt.subscribe(lambda old, new: seen.append((old.rules.project, new.rules.project)))
    assert await rt.refresh() is False
    await _save(sessions, "rules", _renamed(sbr_rules, "renamed"), 0)
    assert await rt.refresh() is True
    assert rt.snapshot.rules.project == "renamed" and rt.snapshot.rules_version == 1
    assert seen == [(sbr_rules.project, "renamed")]
    assert rt.snapshot.text_matcher is rt.snapshot.text_matcher  # 每个版本只编译一次


async def test_refresh_keeps_snapshot_on_invalid_revision(sessions, settings, sbr_rules) -> None:
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t")
    await _save(sessions, "rules", _renamed(sbr_rules, "v1"), 0)
    await rt.refresh()
    await _save(sessions, "rules", _renamed(sbr_rules, "v2"), 1)
    async with sessions.begin() as s:  # 模拟升级后旧内容不再合法
        await s.execute(
            update(ConfigRevision).where(ConfigRevision.version == 2).values(content="project: [\n")
        )
    assert await rt.refresh() is False
    assert rt.snapshot.rules.project == "v1"
    assert rt.errors["rules"] is not None and rt.errors["rules"].startswith("v2")
    async with sessions() as s:
        status = {(r.kind): r.error for r in await revisions.statuses(s)}
    assert status["rules"] is not None


async def test_start_skips_invalid_newest_revision(sessions, settings, sbr_rules) -> None:
    await _save(sessions, "rules", _renamed(sbr_rules, "good"), 0)
    await _save(sessions, "rules", _renamed(sbr_rules, "bad"), 1)
    async with sessions.begin() as s:
        await s.execute(
            update(ConfigRevision).where(ConfigRevision.version == 2).values(content="x: [\n")
        )
    rt = await ConfigRuntime.start(settings, sessions, process="api@t")
    assert rt.snapshot.rules.project == "good" and rt.snapshot.rules_version == 1
    assert rt.errors["rules"] is not None


async def test_start_falls_back_to_files_when_db_is_down(settings, sbr_rules) -> None:
    engine = create_async_engine("postgresql+asyncpg://opti:x@127.0.0.1:1/none")
    rt = await ConfigRuntime.start(settings, make_sessionmaker(engine), process="api@t")
    assert rt.snapshot.rules == sbr_rules
    assert await rt.refresh() is False  # 刷新失败保留当前快照
    await engine.dispose()
    org_mod.set_current(None)


async def test_publishes_rules_to_valkey(sessions, settings, sbr_rules) -> None:
    kv = FakeKV()
    rt = await ConfigRuntime.start(settings, sessions, process="api@t", publisher=kv)
    assert '"version": 0' in kv.data[EDGE_RULES_KEY]
    await _save(sessions, "rules", _renamed(sbr_rules, "pub"), 0)
    await rt.refresh()
    assert '"project": "pub"' in kv.data[EDGE_RULES_KEY]


async def test_fallback_api_does_not_downgrade_published_rules(
    sessions, settings, sbr_rules
) -> None:
    kv = FakeKV()
    live = await ConfigRuntime.start(settings, sessions, process="api@live", publisher=kv)
    await _save(sessions, "rules", _renamed(sbr_rules, "new-project"), 0)
    assert await live.refresh() is True
    published = kv.data[EDGE_RULES_KEY]

    unavailable = create_async_engine("postgresql+asyncpg://opti:x@127.0.0.1:1/none")
    try:
        fallback = await ConfigRuntime.start(
            settings, make_sessionmaker(unavailable), process="api@fallback", publisher=kv
        )
        assert fallback.snapshot.rules_version == 0
        assert kv.data[EDGE_RULES_KEY] == published
    finally:
        await unavailable.dispose()


async def test_redis_publisher_rejects_older_version_atomically(valkey_url: str) -> None:
    client = Redis.from_url(valkey_url, decode_responses=True)
    key = f"{EDGE_RULES_KEY}:test:{uuid.uuid4().hex}"
    publisher = RedisRulePublisher(client)
    try:
        newer = json.dumps({"version": 3, "rules": {"project": "new"}})
        older = json.dumps({"version": 2, "rules": {"project": "old"}})
        assert await publisher.publish_if_newer(key, 3, newer)
        assert not await publisher.publish_if_newer(key, 2, older)
        assert await client.get(key) == newer
    finally:
        await client.delete(key)
        await client.aclose()


async def test_refresh_keeps_the_newer_snapshot_when_calls_overlap(
    sessions, settings, sbr_rules, monkeypatch
) -> None:
    # 第一次读到 head 后停住。没有锁时第二次会先保存并刷新；第一次醒来不能盖掉新快照。
    rt = await ConfigRuntime.start(settings, sessions, process="worker@t")
    await _save(sessions, "rules", _renamed(sbr_rules, "stale"), 0)
    seen = asyncio.Event()
    resume = asyncio.Event()
    calls = 0
    original = revisions.heads

    async def heads(s: AsyncSession) -> dict[str, revisions.Head]:
        nonlocal calls
        found = await original(s)
        calls += 1
        if calls == 1:
            seen.set()
            await asyncio.wait_for(resume.wait(), timeout=5)
        return found

    monkeypatch.setattr(revisions, "heads", heads)

    async def refresh_after_save() -> None:
        await _save(sessions, "rules", _renamed(sbr_rules, "newer"), 1)
        await rt.refresh()

    first = asyncio.create_task(rt.refresh())
    second: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(seen.wait(), timeout=5)
        second = asyncio.create_task(refresh_after_save())
        held = any(
            isinstance(value, asyncio.Lock) and value.locked() for value in vars(rt).values()
        )
        if not held:  # 无锁时第二次会先跑完；有锁时在这里死等会卡死
            await asyncio.wait_for(second, timeout=5)
        resume.set()
        await asyncio.wait_for(first, timeout=5)
        await asyncio.wait_for(second, timeout=5)
    finally:
        resume.set()
        pending = [task for task in (first, second) if task is not None and not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    assert rt.snapshot.rules.project == "newer"


async def test_heartbeat_set_in_flight_cannot_overwrite_newer_rules(
    sessions, settings, sbr_rules
) -> None:
    # 心跳的 SET 还在飞时，保存并 refresh 发布了新规则。结束后 Valkey 里必须是新正文。
    class GateKV(FakeKV):
        def __init__(self) -> None:
            super().__init__()
            self.hold = False
            self.entered = asyncio.Event()
            self.release = asyncio.Event()
            self.finished = asyncio.Event()

        async def set(self, name: str, value: str) -> bool:
            blocked = self.hold
            if blocked:
                self.hold = False
                self.entered.set()
                await asyncio.wait_for(self.release.wait(), timeout=5)
            self.data[name] = value
            if blocked:
                self.finished.set()
            return True

    kv = GateKV()
    rt = await ConfigRuntime.start(settings, sessions, process="api@t", publisher=kv)
    rt._published = time.monotonic() - HEARTBEAT_SECONDS - 1
    kv.hold = True
    loop = asyncio.create_task(rt.run(0))
    second: asyncio.Task[None] | None = None

    async def save_and_refresh() -> None:
        await _save(sessions, "rules", _renamed(sbr_rules, "newer"), 0)
        await rt.refresh()

    try:
        await asyncio.wait_for(kv.entered.wait(), timeout=5)
        second = asyncio.create_task(save_and_refresh())
        held = any(
            isinstance(value, asyncio.Lock) and value.locked() for value in vars(rt).values()
        )
        if not held:  # 无锁时第二次会先发布；有锁时先等会和心跳的 SET 死锁
            await asyncio.wait_for(second, timeout=5)
        kv.release.set()
        await asyncio.wait_for(kv.finished.wait(), timeout=5)
        await asyncio.wait_for(second, timeout=5)
    finally:
        kv.release.set()
        loop.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await loop
        if second is not None and not second.done():
            second.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await second
    assert '"project": "newer"' in kv.data[EDGE_RULES_KEY]


async def test_failed_publish_is_retried_on_the_next_refresh(sessions, settings, sbr_rules) -> None:
    class FlakyKV(FakeKV):
        def __init__(self) -> None:
            super().__init__()
            self.fail = False

        async def set(self, name: str, value: str) -> bool:
            if self.fail:
                raise RuntimeError("down")
            return await super().set(name, value)

    kv = FlakyKV()
    rt = await ConfigRuntime.start(settings, sessions, process="api@t", publisher=kv)
    kv.fail = True
    await _save(sessions, "rules", _renamed(sbr_rules, "retry"), 0)
    assert await rt.refresh() is True
    assert rt.snapshot.rules.project == "retry"
    assert '"project": "retry"' not in kv.data[EDGE_RULES_KEY]
    kv.fail = False
    assert await rt.refresh() is False  # 快照已换过；发布失败不能干等心跳间隔
    assert '"project": "retry"' in kv.data[EDGE_RULES_KEY]


def test_static_snapshot(sbr_rules, tmp_path, monkeypatch) -> None:
    org_file = tmp_path / "organization.yaml"
    org_file.write_text("name: File Org\n", encoding="utf-8")
    monkeypatch.setenv("OPTI_ORGANIZATION", str(org_file))
    org_mod._file_organization.cache_clear()
    try:
        rt = ConfigRuntime.static(sbr_rules)
        assert rt.snapshot.rules is sbr_rules and rt.snapshot.organization.name == "Open-TI user"
        other = ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "x"}))
        seen: list[str] = []
        unsubscribe = rt.subscribe(lambda _o, n: seen.append(n.rules.project))
        rt.apply(other)
        unsubscribe()
        rt.apply(ConfigSnapshot.of(sbr_rules))
        assert seen == ["x"]
    finally:
        org_mod.set_current(None)
    try:
        assert org_mod.current_organization().name == "File Org"
    finally:
        org_mod._file_organization.cache_clear()
