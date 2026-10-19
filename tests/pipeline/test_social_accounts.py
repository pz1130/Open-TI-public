import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest
from sqlalchemy import func, select, update

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Severity
from opti.core.social import Profile
from opti.db import repo
from opti.db.models import AccountCandidate, Alert, AppUser, Finding, ProtectedAccount
from opti.enrichers.social import SUPPORTED_TYPES
from opti.pipeline import social_accounts, submissions
from opti.pipeline.app import App, build_app
from opti.sdk.base import Enricher
from opti.sdk.models import Tier
from opti.sdk.testing import make_context
from opti.settings import Settings

pytestmark = pytest.mark.db

OFFICIAL = {"dhash": "f0f0f0f00f0f0f0f", "sha256": "a" * 64}
COPY = {"dhash": "f0f0f0f00f0f0f08", "sha256": "b" * 64}  # 汉明距离 3
OTHER = {"dhash": "0f0f0f0ff0f0f0f0", "sha256": "c" * 64}


def profile(did: str, handle: str, name: str, **kw: Any) -> dict[str, Any]:
    return Profile(
        platform_id=did,
        handle=handle,
        display_name=name,
        profile_url=f"https://bsky.app/profile/{did}",
        registered_at=kw.get("registered_at"),
        bio=kw.get("bio", ""),
        avatar_url=kw.get("avatar"),
        suspended=kw.get("suspended", False),
    ).to_json()


SELF = profile(
    "did:plc:official", "sbrank.bsky.social", "Sample Brand", avatar="av-official"
)
IMPOSTOR = profile(
    "did:plc:impostor", "sbrank-support.bsky.social", "Sample Brand", avatar="av-copy"
)
FAN = profile(
    "did:plc:fan", "sbrank.fans.bsky.social", "Sample Brand fans", avatar="av-other"
)
ALLOWED = profile("did:plc:allowed", "sbr-asia.bsky.social", "Sample Brand Asia")
OWN_DOMAIN = profile("did:plc:own", "news.sbr.int", "Sample Brand News", avatar="av-copy")
UNRELATED = profile("did:plc:x", "someone.bsky.social", "Someone Else", avatar="av-other")


class FakePlatform(Enricher):
    id: ClassVar[str] = "social_bluesky"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = SUPPORTED_TYPES

    def __init__(self, ctx: Any, state: dict[str, Any]) -> None:
        super().__init__(ctx, {})
        self.state = state
        self.calls: list[tuple[str, str]] = []

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        self.calls.append((entity_type, value))
        hook: Callable[[str, str], Awaitable[None]] | None = self.state.get("hook")
        if hook is not None:
            await hook(entity_type, value)
        result: dict[str, Any] = self.state[entity_type](value)
        return result


def default_state() -> dict[str, Any]:
    avatars = {"av-official": OFFICIAL, "av-copy": COPY, "av-other": OTHER}
    return {
        "social_profile": lambda v: (
            {"profile": SELF}
            if v in ("sbrank.bsky.social", "did:plc:official")
            else {"not_found": True}
        ),
        "social_search": lambda _: {
            "profiles": [SELF, IMPOSTOR, FAN, ALLOWED, OWN_DOMAIN, UNRELATED]
        },
        "social_avatar": lambda v: avatars.get(v, {"error": "unsupported_image"}),
    }


@pytest.fixture
async def world(
    clean_db: str, sbr_rules: ProjectRules, sbr_rules_path: Path
) -> AsyncIterator[tuple[App, FakePlatform, int]]:
    ctx = make_context(sbr_rules)
    platform = FakePlatform(ctx, default_state())
    app = await build_app(
        Settings(database_url=clean_db, rules_path=sbr_rules_path),
        enrichers={"social_bluesky": platform},
        sinks=[],
    )
    now = datetime.now(UTC)
    async with app.sessions.begin() as session:
        await repo.upsert_project(session, app.rules)
        row = ProtectedAccount(
            project_id=app.rules.project,
            platform="bluesky",
            handle="sbrank.bsky.social",
            label="官方账号",
            allowed_accounts=["did:plc:allowed"],
            created_at=now,
            next_check_at=now,
        )
        session.add(row)
        await session.flush()
        account_id = row.id
    try:
        yield app, platform, account_id
    finally:
        await app.close()
        await ctx.http().aclose()


async def rows(app: App) -> dict[str, AccountCandidate]:
    async with app.sessions() as session:
        found = (await session.scalars(select(AccountCandidate))).all()
    return {row.platform_account_id: row for row in found}


async def alerts(app: App) -> list[Alert]:
    async with app.sessions() as session:
        return list((await session.scalars(select(Alert).order_by(Alert.id))).all())


async def account(app: App, account_id: int) -> ProtectedAccount:
    async with app.sessions() as session:
        row = await session.get(ProtectedAccount, account_id)
        assert row is not None
        return row


async def test_check_scores_saves_and_alerts_only_real_impostors(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)

    found = await rows(app)
    # 自身、已知合法账号、官方域名下的账号、名称不相似的账号都不保存
    assert set(found) == {"did:plc:impostor", "did:plc:fan"}
    impostor, fan = found["did:plc:impostor"], found["did:plc:fan"]
    assert impostor.score == 68 and impostor.avatar_sha256 == "b" * 64
    assert impostor.signals["breakdown"] == {"display_same": 20, "handle_contains": 8, "avatar": 40}
    assert fan.score < 40 and fan.finding_id is not None  # 低危：记发现，不开告警

    opened = await alerts(app)
    assert len(opened) == 1
    alert = opened[0]
    assert alert.severity == Severity.HIGH.value
    assert alert.evidence_status == "none"  # 平台主页不让沙箱访问
    assert alert.routing["category"] == Category.IMPERSONATION_ACCOUNT.value
    assert alert.routing["url"] == "https://bsky.app/profile/did:plc:impostor"
    assert "avatar" in alert.routing["reasons"]

    async with app.sessions() as session:
        finding = await session.get(Finding, impostor.finding_id)
        assert finding is not None
        assert finding.match["social"]["protected_handle"] == "sbrank.bsky.social"
        assert finding.match["platform"] == "bluesky"

    row = await account(app, account_id)
    assert row.platform_id == "did:plc:official"
    assert row.display_name == "Sample Brand"
    assert (row.avatar_dhash, row.avatar_sha256) == (OFFICIAL["dhash"], OFFICIAL["sha256"])
    assert row.error is None and row.scan_started_at is None
    assert row.next_check_at > datetime.now(UTC) + timedelta(hours=23)
    # 头像只为名称相似、未被排除的账号下载：粉丝号与冒充号各一次，无关账号与官方域名账号不下载
    assert platform.calls.count(("social_avatar", "av-other")) == 1
    assert platform.calls.count(("social_avatar", "av-copy")) == 1


async def test_same_severity_does_not_realert_but_escalation_does(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    assert await social_accounts.check_account(app, account_id, force=True)
    assert len(await alerts(app)) == 1

    fan = {**FAN, "avatar_url": "av-copy", "bio": "Official support"}
    platform.state["social_search"] = lambda _: {"profiles": [IMPOSTOR, fan]}
    assert await social_accounts.check_account(app, account_id, force=True)
    opened = await alerts(app)
    assert len(opened) == 2 and opened[1].severity == Severity.HIGH.value


async def test_renamed_account_is_the_same_candidate(world: tuple[App, FakePlatform, int]) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    renamed = {**IMPOSTOR, "handle": "sbrank-help.bsky.social"}
    platform.state["social_search"] = lambda _: {"profiles": [renamed]}
    assert await social_accounts.check_account(app, account_id, force=True)
    found = await rows(app)
    assert found["did:plc:impostor"].handle == "sbrank-help.bsky.social"
    assert len(await alerts(app)) == 1


async def test_not_due_or_leased_checks_are_skipped(world: tuple[App, FakePlatform, int]) -> None:
    app, _, account_id = world
    assert await social_accounts.check_account(app, account_id)
    assert not await social_accounts.check_account(app, account_id)  # 24 小时后才到期
    async with app.sessions.begin() as session:
        await session.execute(
            update(ProtectedAccount).values(
                scan_started_at=datetime.now(UTC) - timedelta(minutes=5)
            )
        )
    assert not await social_accounts.check_account(app, account_id, force=True)  # 租约中
    async with app.sessions.begin() as session:
        await session.execute(update(ProtectedAccount).values(enabled=False, scan_started_at=None))
    assert not await social_accounts.check_account(app, account_id, force=True)


async def test_results_are_dropped_when_edited_during_the_check(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world

    async def edit(entity_type: str, _: str) -> None:
        if entity_type == "social_search":
            async with app.sessions.begin() as session:
                await session.execute(update(ProtectedAccount).values(scan_started_at=None))

    platform.state["hook"] = edit
    assert not await social_accounts.check_account(app, account_id)
    assert await rows(app) == {}
    assert await alerts(app) == []


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"social_search": lambda _: {"error": "http_503"}}, "search_failed"),
        (
            {"social_search": lambda _: {"error": "all_instances_failed", "failed_instances": 2}},
            "search_failed",
        ),
    ],
)
async def test_platform_failures_retry_within_an_hour(
    world: tuple[App, FakePlatform, int], change: dict[str, Any], error: str
) -> None:
    app, platform, account_id = world
    platform.state.update(change)
    assert await social_accounts.check_account(app, account_id)
    row = await account(app, account_id)
    assert row.error == error
    assert row.next_check_at < datetime.now(UTC) + timedelta(hours=2)


async def test_missing_adapter_retries_within_an_hour(clean_db: str, sbr_rules_path: Path) -> None:
    app = await build_app(
        Settings(database_url=clean_db, rules_path=sbr_rules_path), enrichers={}, sinks=[]
    )
    try:
        now = datetime.now(UTC)
        async with app.sessions.begin() as session:
            await repo.upsert_project(session, app.rules)
            row = ProtectedAccount(
                project_id=app.rules.project,
                platform="mastodon",
                handle="sbrank@mastodon.social",
                created_at=now,
                next_check_at=now,
            )
            session.add(row)
            await session.flush()
            account_id = row.id
        assert await social_accounts.check_account(app, account_id)
        saved = await account(app, account_id)
        assert saved.error == "adapter_disabled"
        assert saved.next_check_at < datetime.now(UTC) + timedelta(hours=2)
    finally:
        await app.close()


async def test_missing_protected_account_is_reported_without_searching(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    platform.state["social_profile"] = lambda _: {"not_found": True}
    assert await social_accounts.check_account(app, account_id)
    row = await account(app, account_id)
    assert row.error == "protected_not_found"
    assert not any(kind == "social_search" for kind, _ in platform.calls)
    assert row.next_check_at > datetime.now(UTC) + timedelta(hours=23)


async def test_profile_failure_keeps_stored_profile_and_never_fetched_avatar_is_skipped(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    platform.state["social_profile"] = lambda _: {"error": "http_503"}
    assert await social_accounts.check_account(app, account_id)
    row = await account(app, account_id)
    assert row.error == "profile_failed; official_avatar_missing"
    # 从未取到官方资料：没有显示名与官方头像可比，只靠账号名相似不够 20 分，不保存也不下载头像
    assert await rows(app) == {}
    assert not any(kind == "social_avatar" for kind, _ in platform.calls)

    platform.state.update(default_state())
    assert await social_accounts.check_account(app, account_id, force=True)
    platform.calls.clear()
    platform.state["social_profile"] = lambda _: {"error": "http_503"}
    assert await social_accounts.check_account(app, account_id, force=True)
    row = await account(app, account_id)
    assert row.error == "profile_failed"  # 沿用上次保存的显示名与官方头像
    assert ("social_avatar", "av-copy") in platform.calls


async def test_gone_candidates_with_open_alerts_are_marked_not_closed(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    base = platform.state["social_profile"]
    platform.state["social_profile"] = lambda v: (
        {"not_found": True} if v == "did:plc:impostor" else base(v)
    )
    platform.state["social_search"] = lambda _: {"profiles": []}
    assert await social_accounts.check_account(app, account_id, force=True)
    assert ("social_profile", "did:plc:impostor") in platform.calls
    assert ("social_profile", "did:plc:fan") not in platform.calls  # 低危没有告警，不复查
    impostor = (await rows(app))["did:plc:impostor"]
    assert impostor.gone_at is not None
    async with app.sessions() as session:
        finding = await session.get(Finding, impostor.finding_id)
        assert finding is not None and finding.match["social"]["gone_at"]
    assert [a.status for a in await alerts(app)] == ["open"]


async def test_suspended_profile_counts_as_gone(world: tuple[App, FakePlatform, int]) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    base = platform.state["social_profile"]
    suspended = {**IMPOSTOR, "suspended": True}
    platform.state["social_profile"] = lambda v: (
        {"profile": suspended} if v == "did:plc:impostor" else base(v)
    )
    platform.state["social_search"] = lambda _: {"profiles": []}
    assert await social_accounts.check_account(app, account_id, force=True)
    assert (await rows(app))["did:plc:impostor"].gone_at is not None


async def test_automatic_result_never_lowers_an_analyst_submission(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, _, account_id = world
    async with app.sessions.begin() as session:
        await repo.upsert_project(session, app.rules)
        analyst = AppUser(
            username="alice", password_hash="!", roles=["analyst"], created_at=datetime.now(UTC)
        )
        session.add(analyst)
        await session.flush()
        await submissions.submit(
            session,
            submissions.Submission(
                url="https://bsky.app/profile/did:plc:impostor",
                category=Category.FRAUD_SCAM,
                severity=Severity.CRITICAL,
                description="冒充客服收取手续费",
            ),
            rules=app.rules,
            cfg=app.takedown,
            user_id=analyst.id,
            now=datetime.now(UTC),
        )
    assert await social_accounts.check_account(app, account_id)
    async with app.sessions() as session:
        finding = (
            await session.scalars(select(Finding).where(Finding.category == "fraud_scam"))
        ).one()
        assert finding.severity == Severity.CRITICAL.value
        assert finding.match["manual"]["description"] == "冒充客服收取手续费"
        assert finding.match["social"]["handle"] == "sbrank-support.bsky.social"
        count = await session.scalar(select(func.count()).select_from(Alert))
    assert count == 1  # 已有人工告警，级别未升高，不另开


async def test_whole_check_times_out(
    world: tuple[App, FakePlatform, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, platform, account_id = world
    monkeypatch.setattr(social_accounts, "CHECK_TIMEOUT", 0.05)

    async def slow(entity_type: str, _: str) -> None:
        if entity_type == "social_search":
            await asyncio.sleep(1)

    platform.state["hook"] = slow
    assert await social_accounts.check_account(app, account_id)
    row = await account(app, account_id)
    assert row.error == "scan_timeout"
    assert row.next_check_at < datetime.now(UTC) + timedelta(hours=2)


async def test_scheduler_queues_due_accounts_outside_their_lease(
    world: tuple[App, FakePlatform, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    from opti.pipeline import tasks

    app, _, account_id = world

    async def get_app() -> App:
        return app

    queued: list[tuple[int, bool]] = []

    async def queue(id_: int, force: bool) -> None:
        queued.append((id_, force))

    monkeypatch.setattr(tasks, "get_app", get_app)
    monkeypatch.setattr(tasks.check_protected_account, "kiq", queue)
    assert await tasks.check_social_accounts() == 1
    assert queued == [(account_id, False)]
    async with app.sessions.begin() as session:
        await session.execute(update(ProtectedAccount).values(scan_started_at=datetime.now(UTC)))
    assert await tasks.check_social_accounts() == 0
    async with app.sessions.begin() as session:
        await session.execute(update(ProtectedAccount).values(scan_started_at=None, enabled=False))
    assert await tasks.check_social_accounts() == 0


async def test_renamed_protected_bluesky_account_is_looked_up_by_did(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    renamed = {**SELF, "handle": "sbr-official.bsky.social"}
    platform.state["social_profile"] = lambda v: (
        {"profile": renamed} if v == "did:plc:official" else {"not_found": True}
    )
    assert await social_accounts.check_account(app, account_id, force=True)
    assert (await account(app, account_id)).error is None
    assert ("social_profile", "did:plc:official") in platform.calls
    # 改名后账号名同步刷新，搜索词也用新的本地部分
    assert (await account(app, account_id)).handle == "sbr-official.bsky.social"
    assert ("social_search", "sbr-official") in platform.calls


async def test_one_impostor_of_two_protected_accounts_alerts_once(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    now = datetime.now(UTC)
    async with app.sessions.begin() as session:
        second = ProtectedAccount(
            project_id=app.rules.project,
            platform="bluesky",
            handle="sbrank-cn.bsky.social",
            created_at=now,
            next_check_at=now,
        )
        session.add(second)
        await session.flush()
        second_id = second.id
    base = platform.state["social_profile"]
    platform.state["social_profile"] = lambda v: (
        {"profile": {**SELF, "platform_id": "did:plc:cn", "handle": "sbrank-cn.bsky.social"}}
        if v == "sbrank-cn.bsky.social"
        else base(v)
    )
    platform.state["social_search"] = lambda _: {"profiles": [IMPOSTOR]}
    assert await social_accounts.check_account(app, account_id)
    assert await social_accounts.check_account(app, second_id)
    assert len(await alerts(app)) == 1
    async with app.sessions() as session:
        owners = (await session.scalars(select(AccountCandidate.protected_id))).all()
    assert sorted(owners) == sorted([account_id, second_id])


async def test_unequal_scores_from_two_protected_accounts_do_not_realert(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    now = datetime.now(UTC)
    async with app.sessions.begin() as session:
        second = ProtectedAccount(
            project_id=app.rules.project,
            platform="bluesky",
            handle="sbrank-cn.bsky.social",
            created_at=now,
            next_check_at=now,
        )
        session.add(second)
        await session.flush()
        second_id = second.id
    base = platform.state["social_profile"]
    # 第二个受保护账号没有头像：同一冒充号对它只算名称，得分低于对第一个账号
    platform.state["social_profile"] = lambda v: (
        {
            "profile": {
                **SELF,
                "platform_id": "did:plc:cn",
                "handle": "sbrank-cn.bsky.social",
                "avatar_url": None,
            }
        }
        if v in ("sbrank-cn.bsky.social", "did:plc:cn")
        else base(v)
    )
    platform.state["social_search"] = lambda _: {"profiles": [IMPOSTOR]}
    for _ in range(3):
        assert await social_accounts.check_account(app, account_id, force=True)
        assert await social_accounts.check_account(app, second_id, force=True)
    opened = await alerts(app)
    assert [a.status for a in opened] == ["open"]
    async with app.sessions() as session:
        finding = (await session.scalars(select(Finding))).one()
    assert finding.severity == Severity.HIGH.value  # 取各受保护账号中的最高分，不来回跳


async def test_temporary_avatar_failure_keeps_the_stored_hash(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    avatars = platform.state["social_avatar"]
    platform.state["social_avatar"] = lambda v: (
        {"error": "http_429"} if v == "av-copy" else avatars(v)
    )
    assert await social_accounts.check_account(app, account_id, force=True)
    impostor = (await rows(app))["did:plc:impostor"]
    assert impostor.score == 68 and impostor.avatar_sha256 == "b" * 64
    platform.state["social_avatar"] = avatars
    assert await social_accounts.check_account(app, account_id, force=True)
    assert [a.status for a in await alerts(app)] == ["open"]


async def test_avatar_downloads_are_capped_per_run(
    world: tuple[App, FakePlatform, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, platform, account_id = world
    monkeypatch.setattr(social_accounts, "MAX_AVATARS", 1)
    assert await social_accounts.check_account(app, account_id)
    downloads = [v for kind, v in platform.calls if kind == "social_avatar" and v != "av-official"]
    assert downloads == ["av-copy"]
    assert (await rows(app))["did:plc:impostor"].score == 68


async def test_timeout_keeps_the_results_collected_so_far(
    world: tuple[App, FakePlatform, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, platform, account_id = world
    monkeypatch.setattr(social_accounts, "CHECK_TIMEOUT", 0.5)

    async def slow(entity_type: str, value: str) -> None:
        if entity_type == "social_avatar" and value == "av-other":
            await asyncio.sleep(5)

    platform.state["hook"] = slow
    assert await social_accounts.check_account(app, account_id)
    row = await account(app, account_id)
    assert row.error == "scan_timeout"
    assert row.next_check_at < datetime.now(UTC) + timedelta(hours=2)
    assert set(await rows(app)) == {"did:plc:impostor"}  # 超时前已打分的冒充号已保存
    assert len(await alerts(app)) == 1


async def test_taken_down_accounts_in_search_are_not_alerted(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    platform.state["social_search"] = lambda _: {"profiles": [{**IMPOSTOR, "suspended": True}]}
    assert await social_accounts.check_account(app, account_id)
    assert await rows(app) == {}
    assert await alerts(app) == []


async def test_taken_down_known_candidate_in_search_is_marked_gone(
    world: tuple[App, FakePlatform, int],
) -> None:
    app, platform, account_id = world
    assert await social_accounts.check_account(app, account_id)
    platform.state["social_search"] = lambda _: {"profiles": [{**FAN, "suspended": True}]}
    assert await social_accounts.check_account(app, account_id, force=True)
    assert (await rows(app))["did:plc:fan"].gone_at is not None
