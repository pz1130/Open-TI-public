import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, severity_for
from opti.core.secretbox import Keyring
from opti.db import repo
from opti.db.engine import make_sessionmaker
from opti.db.models import Adjudication, LlmProvider, LlmSettings
from opti.organization import Organization
from opti.pipeline import adjudication, llm_runtime

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
RING = Keyring(bytes(range(32)))
KEY = "sk-" + "live-" + "abcdefghijklmnop"
ORG = Organization(name="Sample Brand", short_name="SBR")
ANSWER = '{"is_about_org": "no", "category": "unrelated", "confidence": 0.7, "rationale": "r", "summary": "s"}'


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()


async def _provider(s: AsyncSession, name: str, preset: str = "deepseek", key: str | None = KEY,
                    ring: Keyring = RING) -> int:  # fmt: skip
    url = "http://vllm:8000/v1" if preset == "selfhosted" else "https://api.deepseek.com/v1"
    row = LlmProvider(name=name, preset=preset, base_url=url, model="m-" + name, json_mode=True,
                      temperature=0.0, timeout_seconds=30, created_at=NOW, updated_at=NOW)  # fmt: skip
    s.add(row)
    await s.flush()
    if key is not None:
        row.api_key_enc = ring.encrypt(key, aad=llm_runtime.aad(row.id, "api_key"))
        row.api_key_hint = key[-4:]
    return row.id


async def _settings(s: AsyncSession, **kw: object) -> None:
    base: dict[str, object] = dict(
        id=1, enabled=True, gray_zone_low=30, gray_zone_high=70, max_per_run=20, max_attempts=3,
        max_wait_minutes=30, summary_language="English", updated_at=NOW,
    )  # fmt: skip
    base.update(kw)
    await s.merge(LlmSettings(**base))


async def test_disabled_and_missing(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions() as s:
        assert await llm_runtime.load(s, RING) == llm_runtime.Runtime(None)
    async with sessions.begin() as s:
        await _settings(s, enabled=False)
    async with sessions() as s:
        assert (await llm_runtime.load(s, RING)).cfg is None
        assert (await llm_runtime.load(s, RING, include_disabled=True)) == llm_runtime.Runtime(None)
    async with sessions.begin() as s:
        p = await _provider(s, "Local", preset="selfhosted", key=None)
        await _settings(s, enabled=False, primary_id=p)
    async with sessions() as s:
        assert (await llm_runtime.load(s, RING)).cfg is None
        early = await llm_runtime.load(s, RING, include_disabled=True)  # 命令行：启用前先评测
        assert early.cfg is not None and early.primary is not None and early.primary.name == "Local"


async def test_loads_and_decrypts(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions.begin() as s:
        p = await _provider(s, "DeepSeek")
        b = await _provider(s, "Local", preset="selfhosted", key=None)
        await _settings(s, primary_id=p, backup_id=b, gray_zone_low=20, code_enabled=True)
    async with sessions() as s:
        rt = await llm_runtime.load(s, RING)
    assert (
        rt.cfg is not None and rt.cfg.gray_zone == (20, 70) and rt.cfg.summary_language == "English"
    )
    assert rt.cfg.code_enabled is True and llm_runtime.settings_cfg(None).code_enabled is False
    assert rt.primary is not None and rt.primary.api_key == KEY and rt.primary.auth == "bearer"
    assert rt.backup is not None and rt.backup.api_key is None and rt.problem is None
    assert KEY not in repr(rt)


async def test_unavailable_primary_disables(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions.begin() as s:
        p = await _provider(s, "DeepSeek")
        await _settings(s, primary_id=p)
    async with sessions() as s:
        no_ring = await llm_runtime.load(s, None)
        other = await llm_runtime.load(s, Keyring(bytes(32)))
    assert no_ring.cfg is None and "凭据加密主密钥" in (no_ring.problem or "")
    assert (
        other.cfg is None
        and "无法解密" in (other.problem or "")
        and KEY not in (other.problem or "")
    )
    async with sessions.begin() as s:
        row = await s.get(LlmProvider, p)
        assert row is not None
        row.api_key_enc = None
    async with sessions() as s:
        assert "缺少 API 密钥" in ((await llm_runtime.load(s, RING)).problem or "")


async def test_unavailable_backup_keeps_primary(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions.begin() as s:
        p = await _provider(s, "Local", preset="selfhosted", key=None)
        b = await _provider(s, "DeepSeek", key=None)
        await _settings(s, primary_id=p, backup_id=b)
    async with sessions() as s:
        rt = await llm_runtime.load(s, RING)
    assert rt.cfg is not None and rt.backup is None and "备用" in (rt.problem or "")


async def test_cache_refreshes_after_ttl(sessions: async_sessionmaker[AsyncSession]) -> None:
    now = [0.0]
    cache = llm_runtime.RuntimeCache(RING, ttl=30, clock=lambda: now[0])
    async with sessions() as s:
        assert await cache.cfg(s) is None
    async with sessions.begin() as s:
        p = await _provider(s, "Local", preset="selfhosted", key=None)
        await _settings(s, primary_id=p)
    async with sessions() as s:
        assert await cache.cfg(s) is None  # 缓存期内
        now[0] = 31.0
        assert await cache.cfg(s) is not None  # 不用重启，30 秒后生效
    assert await llm_runtime.StaticLlm(None).cfg(None) is None  # type: ignore[arg-type]


async def test_worker_round_uses_database_provider(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    async with sessions.begin() as s:
        p = await _provider(s, "DeepSeek")
        await _settings(s, primary_id=p)
        await repo.upsert_project(s, sbr_rules)
        entity = await repo.upsert_entity(s, "document", "cluster:9", NOW)
        score = Score(50, severity_for(50), Category.NEGATIVE_PRESS, {"base": 35, "boosters": 15})
        match = {"terms": ["SBR"], "contexts": ["The SBR faces a lawsuit"],
                 "document": {"title": "SBR lawsuit", "source_name": "News"}}  # fmt: skip
        up = await repo.upsert_finding(s, project_id=sbr_rules.project, entity=entity, score=score,
                                       match=match, source="gdelt_doc", now=NOW)  # fmt: skip
        await adjudication.request(s, up.finding, hold=score.severity, now=NOW)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": ANSWER}}]})

    async with sessions() as s:
        rt = await llm_runtime.load(s, RING)
    async with llm_runtime.adjudicator(rt, transport=httpx.MockTransport(handler)) as adj:
        assert adj is not None
        await adjudication.run_pending(sessions, adj, cfg=rt.cfg, rules=sbr_rules,
                                       organization=ORG, clock=lambda: NOW)  # fmt: skip
    assert seen[0].headers["authorization"] == f"Bearer {KEY}"
    assert "English" in json.loads(seen[0].content)["messages"][1]["content"]
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        assert (row.status, row.backend, row.model) == ("done", "deepseek", "m-DeepSeek")


async def test_adjudicator_none_when_disabled() -> None:
    async with llm_runtime.adjudicator(llm_runtime.Runtime(None)) as adj:
        assert adj is None


async def test_rekey(sessions: async_sessionmaker[AsyncSession]) -> None:
    old, new = Keyring(bytes(range(32))), bytes(range(32, 64))
    async with sessions.begin() as s:
        pid = await _provider(s, "DeepSeek", ring=old)
        row = await s.get(LlmProvider, pid)
        assert row is not None
        row.proxy_enc = old.encrypt("http://proxy:1", aad=llm_runtime.aad(pid, "proxy"))
    both = Keyring(new, previous=bytes(range(32)))
    async with sessions.begin() as s:
        assert await llm_runtime.rekey(s, both) == 2
    async with sessions.begin() as s:
        assert await llm_runtime.rekey(s, both) == 0  # 已经是新钥
    async with sessions() as s:
        row = await s.get(LlmProvider, pid)
        assert row is not None and row.api_key_enc is not None
        assert Keyring(new).decrypt(row.api_key_enc, aad=llm_runtime.aad(pid, "api_key")) == KEY


def test_sample_input_and_legacy_warning(
    sbr_rules: ProjectRules, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    inp = llm_runtime.sample_input(sbr_rules, ORG)
    assert inp.organization == "Sample Brand" and inp.source == "llm-check"
    legacy = tmp_path / "llm.yaml"
    legacy.write_text("backend: claude\nmodel: x\n", encoding="utf-8")
    llm_runtime.warn_legacy(legacy)
    assert "已不再生效" in caplog.text
    caplog.clear()
    legacy.write_text("backend: none\n", encoding="utf-8")
    llm_runtime.warn_legacy(legacy)
    llm_runtime.warn_legacy(tmp_path / "missing.yaml")
    assert caplog.text == ""


async def test_worker_reports_its_own_view(sessions: async_sessionmaker[AsyncSession]) -> None:
    """worker 与 API 是不同进程：worker 缺主密钥时，页面也要能看到。"""
    async with sessions() as s, s.begin():
        await llm_runtime.report(s, llm_runtime.Runtime(None), now=NOW)  # 没有设置行：什么也不做
    async with sessions.begin() as s:
        p = await _provider(s, "DeepSeek")
        await _settings(s, primary_id=p)
    async with sessions() as s, s.begin():
        await llm_runtime.report(s, await llm_runtime.load(s, None), now=NOW)  # worker 没有主密钥
    async with sessions() as s:
        row = await s.get(LlmSettings, 1)
        assert row is not None and row.worker_checked_at == NOW
        assert "凭据加密主密钥" in (row.worker_problem or "") and row.updated_at == NOW
    later = NOW + timedelta(minutes=2)
    async with sessions() as s, s.begin():
        await llm_runtime.report(s, await llm_runtime.load(s, RING), now=later)
    async with sessions() as s:
        row = await s.get(LlmSettings, 1)
        assert row is not None and row.worker_problem is None and row.worker_checked_at == later
