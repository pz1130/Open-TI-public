from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import Alert, DomainObservation, TakedownEvent, WatchedDomain
from opti.takedown import service
from opti.takedown.config import TakedownConfig
from opti.takedown.render import Material
from opti.takedown.service import Actor, TakedownError
from opti.takedown.targets import Target

pytestmark = pytest.mark.db
CFG = TakedownConfig()
TARGET = Target("registrar", "registrar:cheap", "Cheap Registrar LLC", "abuse@registrar.example", None, "rdap_registrar")  # fmt: skip
MATERIAL = Material("Abuse report: sbr-loans[.]com", "body\n")
Seed = Callable[..., Awaitable[Any]]
MakeUser = Callable[[str], Awaitable[int]]


async def _draft(
    session: AsyncSession, seed: Seed, make_user: MakeUser, now: datetime
) -> tuple[Any, Any, int, int]:
    s = await seed("sbr-loans.com")
    alice, bob = await make_user("alice"), await make_user("bob")
    td = await service.create(
        session, project_id=s.alert.project_id, alert_id=s.alert.id, finding_id=s.finding.id,
        host="sbr-loans.com", target=TARGET, material=MATERIAL, language="en-US",
        actor=Actor(alice, "alice"), now=now,
    )  # fmt: skip
    return s, td, alice, bob


async def _removed(session: AsyncSession, td: Any, alice: int, bob: int, now: datetime) -> None:
    await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    await service.transition(
        session, td, "submitted", actor=Actor(alice, "alice"), now=now, cfg=CFG
    )
    await service.transition(session, td, "removed", actor=Actor(alice, "alice"), now=now, cfg=CFG)


async def test_platform_takedown_has_sla_and_no_watch(
    session: AsyncSession, seed: Seed, make_user: MakeUser
) -> None:
    now = datetime.now(UTC)
    seeded = await seed("sbr-loans.com")
    alice, bob = await make_user("alice"), await make_user("bob")
    platform = Target(
        "platform",
        "platform:linkedin",
        "LinkedIn",
        None,
        "https://www.linkedin.com/help/linkedin/answer/a1338436",
        "platform",
    )
    td = await service.create(
        session,
        project_id=seeded.alert.project_id,
        alert_id=seeded.alert.id,
        finding_id=seeded.finding.id,
        host="www.linkedin.com",
        target=platform,
        material=MATERIAL,
        language="en-US",
        actor=Actor(alice, "alice"),
        now=now,
    )
    await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    await service.transition(
        session, td, "submitted", actor=Actor(alice, "alice"), now=now, cfg=CFG
    )
    assert td.due_at == now + timedelta(hours=72)
    await service.transition(session, td, "removed", actor=Actor(alice, "alice"), now=now, cfg=CFG)
    assert td.due_at is None
    watched = (await session.scalars(select(WatchedDomain.domain))).all()
    assert "www.linkedin.com" not in watched


async def test_four_eyes(session: AsyncSession, seed: Seed, make_user: MakeUser) -> None:
    now = datetime.now(UTC)
    _, td, alice, bob = await _draft(session, seed, make_user, now)
    with pytest.raises(TakedownError) as e:
        await service.transition(
            session, td, "approved", actor=Actor(alice, "alice"), now=now, cfg=CFG
        )
    assert e.value.status == 403 and td.state == "draft"
    await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    assert td.state == "approved" and td.approved_by == bob
    events = (
        await session.scalars(
            select(TakedownEvent)
            .where(TakedownEvent.takedown_id == td.id)
            .order_by(TakedownEvent.id)
        )
    ).all()
    assert [(e.actor, e.from_state, e.to_state) for e in events] == [
        ("alice", None, "draft"),
        ("bob", "draft", "approved"),
    ]


async def test_edit_after_approval_resets(
    session: AsyncSession, seed: Seed, make_user: MakeUser
) -> None:
    now = datetime.now(UTC)
    _, td, alice, bob = await _draft(session, seed, make_user, now)
    await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    await service.edit(
        session, td, subject="New\nsubject", body="changed\n", actor=Actor(alice, "alice"), now=now
    )
    assert td.state == "draft" and td.approved_by is None and td.approved_at is None
    assert td.subject == "New subject" and td.body == "changed\n"
    await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    await service.transition(
        session, td, "submitted", actor=Actor(alice, "alice"), now=now, cfg=CFG
    )
    with pytest.raises(TakedownError) as e:
        await service.edit(session, td, subject="x", body="y", actor=Actor(alice, "alice"), now=now)
    assert e.value.status == 409


async def test_illegal_transitions_and_duplicates(
    session: AsyncSession, seed: Seed, make_user: MakeUser
) -> None:
    now = datetime.now(UTC)
    s, td, alice, bob = await _draft(session, seed, make_user, now)
    with pytest.raises(TakedownError) as e:
        await service.transition(
            session, td, "submitted", actor=Actor(alice, "alice"), now=now, cfg=CFG
        )
    assert e.value.status == 409  # 未审批不能提交
    with pytest.raises(TakedownError) as e:
        await service.create(
            session, project_id=s.alert.project_id, alert_id=s.alert.id, finding_id=s.finding.id,
            host="sbr-loans.com", target=TARGET, material=MATERIAL, language="zh-CN",
            actor=Actor(bob, "bob"), now=now,
        )  # fmt: skip
    assert e.value.status == 409  # 同一告警、同一对象已有进行中的投诉
    await _removed(session, td, alice, bob, now)
    with pytest.raises(TakedownError) as e:
        await service.transition(
            session, td, "reappeared", actor=Actor(alice, "alice"), now=now, cfg=CFG
        )
    assert e.value.status == 403  # 复活只能由系统标记


async def test_sla_and_watch_after_removal(
    session: AsyncSession, seed: Seed, make_user: MakeUser
) -> None:
    now = datetime.now(UTC)
    _, td, alice, bob = await _draft(session, seed, make_user, now)
    await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    await service.transition(
        session,
        td,
        "submitted",
        actor=Actor(alice, "alice"),
        now=now,
        cfg=CFG,
        external_ref=" CASE-1 ",
    )
    assert td.due_at == now + timedelta(hours=72) and td.external_ref == "CASE-1"
    ack = now + timedelta(hours=10)
    await service.transition(
        session, td, "acknowledged", actor=Actor(alice, "alice"), now=ack, cfg=CFG
    )
    assert td.due_at == ack + timedelta(hours=72)
    done = now + timedelta(days=1)
    await service.transition(session, td, "removed", actor=Actor(alice, "alice"), now=done, cfg=CFG)
    assert td.due_at is None and td.resolved_at == done
    wd = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "sbr-loans.com"))
    assert (
        wd is not None and wd.expires_at == done + timedelta(days=90) and wd.next_check_at <= done
    )


def _obs(wd: WatchedDomain, state: str, changes: list[str], at: datetime) -> DomainObservation:
    return DomainObservation(
        watched_domain_id=wd.id,
        observed_at=at,
        state=state,
        fingerprint={},
        changes=changes,
        data={},
    )


async def test_reappearance_rules(session: AsyncSession, seed: Seed, make_user: MakeUser) -> None:
    now = datetime.now(UTC)
    s, td, alice, bob = await _draft(session, seed, make_user, now)
    await _removed(session, td, alice, bob, now)
    wd = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "sbr-loans.com"))
    assert wd is not None
    later = now + timedelta(hours=4)
    # 托管商的"账户已暂停"页面：一直可访问、只是内容变了 —— 不是复活
    assert (
        await service.on_recheck(
            session, wd, _obs(wd, "live", ["title_changed", "content_changed"], later), now=later
        )
        == []
    )
    assert (
        await service.on_recheck(
            session, wd, _obs(wd, "parked", ["state:live->parked"], later), now=later
        )
        == []
    )
    # 下架之前的观测不算
    before = now - timedelta(hours=1)
    assert (
        await service.on_recheck(
            session, wd, _obs(wd, "live", ["state:no_dns->live"], before), now=later
        )
        == []
    )
    [new_id] = await service.on_recheck(
        session, wd, _obs(wd, "live", ["state:no_dns->live"], later), now=later
    )
    assert td.state == "reappeared" and td.reappeared_alert_id == new_id
    alert = await session.get(Alert, new_id)
    assert alert is not None and alert.status == "open" and alert.severity == "high"
    assert alert.routing["reappeared_from_takedown"] == td.id
    assert (await session.get(Alert, s.alert.id)).status == "superseded"  # type: ignore[union-attr]
    # 只触发一次
    again = later + timedelta(hours=4)
    assert await service.on_recheck(session, wd, _obs(wd, "phishing", [], again), now=again) == []


async def test_still_phishing_counts_as_reappeared(
    session: AsyncSession, seed: Seed, make_user: MakeUser
) -> None:
    now = datetime.now(UTC)
    _, td, alice, bob = await _draft(session, seed, make_user, now)
    await _removed(session, td, alice, bob, now)
    wd = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "sbr-loans.com"))
    assert wd is not None
    later = now + timedelta(hours=4)
    assert (
        len(await service.on_recheck(session, wd, _obs(wd, "phishing", [], later), now=later)) == 1
    )
    assert td.state == "reappeared"


async def test_editor_cannot_approve_final_material(session, seed, make_user):
    now = datetime.now(UTC)
    _, td, alice, bob = await _draft(session, seed, make_user, now)
    await service.edit(
        session, td, subject="revised", body="changed", actor=Actor(bob, "bob"), now=now
    )
    with pytest.raises(TakedownError, match="four-eyes"):
        await service.transition(session, td, "approved", actor=Actor(bob, "bob"), now=now, cfg=CFG)
    await service.transition(session, td, "approved", actor=Actor(alice, "alice"), now=now, cfg=CFG)


@pytest.mark.parametrize("before", ["unknown", "parked"])
def test_baseline_or_parked_page_is_not_reappearance(before):
    obs = DomainObservation(state="live", changes=[f"state:{before}->live"], data={})
    assert not service.came_back(obs)


def test_failed_recheck_cannot_confirm_phishing():
    obs = DomainObservation(
        state="phishing", changes=[], data={"http_probe": {"error": "TimeoutError"}}
    )
    assert not service.came_back(obs)


@pytest.mark.parametrize(
    "screenshot", [{"error": "screenshot_disabled"}, {"error": "screenshot_unavailable"}]
)
def test_screenshot_failure_does_not_hide_reappearance(screenshot):
    # 复查记录里的截图结果只是取证状态，域名是否复活由 DNS / HTTP 探测决定
    obs = DomainObservation(
        state="live",
        changes=["state:no_dns->live"],
        data={"dns": {"exists": True, "a": ["45.33.32.156"]}, "screenshot": screenshot},
    )
    assert service.came_back(obs)


async def test_shared_host_reappearance_requires_original_url(session, seed, make_user, sbr_rules):
    from opti.pipeline.enrichment import EnrichmentService
    from opti.sdk.testing import make_context, static_enricher

    now = datetime.now(UTC)
    row = await seed(
        "https://shared.example/sbr/login", entity_type="url", category="phishing_site"
    )
    alice, bob = await make_user("alice"), await make_user("bob")
    td = await service.create(
        session,
        project_id=row.alert.project_id,
        alert_id=row.alert.id,
        finding_id=row.finding.id,
        host="shared.example",
        target=TARGET,
        material=MATERIAL,
        language="en-US",
        actor=Actor(alice, "alice"),
        now=now,
    )
    await _removed(session, td, alice, bob, now)
    wd = await session.scalar(select(WatchedDomain).where(WatchedDomain.domain == "shared.example"))
    obs = DomainObservation(
        state="phishing",
        changes=["state:live->phishing"],
        data={},
        observed_at=now + timedelta(hours=1),
    )
    state = {"reachable": True, "status": 200, "has_password_field": False, "brand_terms": []}
    enrichment = EnrichmentService(
        {
            "http_probe": static_enricher(
                make_context(sbr_rules), "http_probe", lambda value: dict(state), types=("url",)
            )
        }
    )
    assert (
        await service.on_recheck(session, wd, obs, now=obs.observed_at, enrichment=enrichment) == []
    )
    assert td.state == "removed"
    state.update(has_password_field=True, brand_terms=["Example"])
    assert (
        len(await service.on_recheck(session, wd, obs, now=obs.observed_at, enrichment=enrichment))
        == 1
    )
    assert td.state == "reappeared"
