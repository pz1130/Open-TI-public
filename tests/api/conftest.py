from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti import organization as org_mod
from opti.api import security
from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity, severity_for
from opti.db import repo
from opti.db.engine import make_sessionmaker
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore

PASSWORD = "correct horse battery staple"


class MutableClock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now


@dataclass
class ApiWorld:
    app: FastAPI
    sessions: async_sessionmaker[AsyncSession]
    store: MemoryObjectStore
    rules: ProjectRules
    clock: MutableClock
    deps: ApiDeps


@dataclass(frozen=True)
class SeededAlert:
    alert_id: int
    finding_id: int
    entity_id: int


@pytest.fixture
async def api(
    clean_db: str, sbr_rules: ProjectRules, sbr_rules_path: Path
) -> AsyncIterator[ApiWorld]:
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    store, clock = MemoryObjectStore(), MutableClock()
    deps = ApiDeps(
        settings=Settings(database_url=clean_db, cookie_secure=False, rules_path=sbr_rules_path),
        config=ConfigRuntime.static(sbr_rules, sessions=sessions),
        sessions=sessions, store=store, clock=clock,
    )  # fmt: skip
    try:
        yield ApiWorld(create_api(deps), sessions, store, sbr_rules, clock, deps)
    finally:
        org_mod.set_current(None)
        org_mod._file_organization.cache_clear()
        await engine.dispose()


@pytest.fixture
def make_user(api: ApiWorld) -> Callable[..., Awaitable[int]]:
    async def make(
        username: str = "alice", roles: tuple[str, ...] = ("analyst",), password: str = PASSWORD
    ) -> int:
        async with api.sessions.begin() as s:
            user = await security.create_user(
                s, username=username, password=password, roles=list(roles), now=api.clock()
            )
            return user.id

    return make


@pytest.fixture
async def login(api: ApiWorld) -> AsyncIterator[Callable[..., Awaitable[httpx.AsyncClient]]]:
    clients: list[httpx.AsyncClient] = []

    async def do(username: str = "alice", password: str = PASSWORD) -> httpx.AsyncClient:
        c = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.app),
            base_url="http://testserver",
            headers={"X-Requested-With": "opti"},
        )
        clients.append(c)
        r = await c.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return c

    yield do
    for c in clients:
        await c.aclose()


@pytest.fixture
def seed_alert(api: ApiWorld) -> Callable[..., Awaitable[SeededAlert]]:
    async def seed(
        domain: str = "sbr-loans.com", severity: str = "high", category: str = "typosquat_domain",
        match: dict[str, Any] | None = None,
    ) -> SeededAlert:  # fmt: skip
        value = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}[severity]
        assert severity_for(value) == Severity(severity)
        now = api.clock()
        async with api.sessions.begin() as s:
            await repo.upsert_project(s, api.rules)
            e = await repo.upsert_entity(s, "domain", domain, now)
            score = Score(
                value,
                Severity(severity),
                Category(category),
                {"base": 20, "domain_risk": value - 20},
            )
            m = match or {"domain": domain, "registered": domain, "status": "match",
                          "reasons": [{"reason": "brand_label", "where": "registered", "token": "sbr"}]}  # fmt: skip
            up = await repo.upsert_finding(
                s,
                project_id=api.rules.project,
                entity=e,
                score=score,
                match=m,
                source="certstream",
                now=now,
            )
            alert = await repo.open_alert(s, up.finding, Severity(severity), now)
            return SeededAlert(alert.id, up.finding.id, e.id)

    return seed
