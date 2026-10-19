import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from opti.core import policy
from opti.core.config import ProjectRules, load_project_rules
from opti.db.migrate import upgrade
from opti.sdk import config_store

# 测试专用遮蔽密钥（生产无默认值，见 .env.example）
os.environ.setdefault("OPTI_SECRET_MASK_KEY", "test-only-mask-key-" + "0" * 32)

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_leftover_connector_settings() -> Iterator[None]:
    """配置运行时安装的连接器设置是进程级的，测试之间不能串用。"""
    config_store.clear_current()
    policy.install(policy.OperationsConfig())
    yield
    config_store.clear_current()
    policy.install(policy.OperationsConfig())


@pytest.fixture(scope="session")
def sbr_rules_path() -> Path:
    return REPO_ROOT / "config" / "projects" / "sample-brand" / "keywords.yaml"


@pytest.fixture(scope="session")
def sbr_rules(sbr_rules_path: Path) -> ProjectRules:
    return load_project_rules(sbr_rules_path)


ALL_TABLES = (
    "access_role", "permission_set",
    "account_candidate", "protected_account",
    "monitored_certificate", "certificate_monitor",
    "config_secret",
    "config_runtime_status", "config_revision",
    "llm_settings", "llm_provider",
    "dashboard_layout",
    "campaign_member", "campaign",
    "adjudication",
    "report",
    "kev_entry",
    "document",
    "code_repo",
    "leak_post",
    "exposed_account",
    "oidc_login", "takedown_event", "takedown", "api_token",
    "audit_log", "api_session", "feedback", "suppression_rule", "app_user",
    "evidence", "collector_node",
    "alert_finding", "alert", "finding_observation", "finding", "domain_observation",
    "watched_domain", "entity", "connector_cursor", "connector_run", "raw_item", "project",
)  # fmt: skip


@pytest.fixture(scope="session")
def pg_url() -> Iterator[str]:
    external = os.environ.get("OPTI_TEST_DATABASE_URL")
    if external:
        yield external
        return
    try:
        from testcontainers.community.postgres import PostgresContainer

        container = PostgresContainer("postgres:16-alpine", driver="asyncpg")
        container.start()
    except Exception as e:  # Docker 不可用时跳过数据库测试，而不是报错
        pytest.skip(f"无法启动 PostgreSQL 测试容器：{e}")
    try:
        yield container.get_connection_url()
    finally:
        container.stop()


@pytest.fixture(scope="session")
def db_url(pg_url: str) -> str:
    asyncio.run(upgrade(pg_url))
    return pg_url


@pytest.fixture
async def session(db_url: str) -> AsyncIterator[AsyncSession]:
    """每个测试一个外层事务，结束时回滚；被测代码中的 commit/begin 变为保存点。"""
    engine = create_async_engine(db_url)
    async with engine.connect() as conn:
        trans = await conn.begin()
        s = AsyncSession(
            bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield s
        finally:
            await s.close()
            await trans.rollback()
    await engine.dispose()


@pytest.fixture
async def clean_db(db_url: str) -> AsyncIterator[str]:
    """供需要真正提交事务的测试（如 Taskiq 任务）使用：测试结束后清空所有表。"""
    yield db_url
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join(ALL_TABLES)} RESTART IDENTITY CASCADE"))
    await engine.dispose()


@pytest.fixture(scope="session")
def valkey_url() -> Iterator[str]:
    external = os.environ.get("OPTI_TEST_VALKEY_URL")
    if external:
        yield external
        return
    try:
        from testcontainers.community.redis import RedisContainer

        container = RedisContainer("valkey/valkey:8-alpine")
        container.start()
    except Exception as e:  # Docker 不可用时跳过
        pytest.skip(f"无法启动 Valkey 测试容器：{e}")
    try:
        host = container.get_container_host_ip()
        yield f"redis://{host}:{container.get_exposed_port(6379)}/0"
    finally:
        container.stop()
