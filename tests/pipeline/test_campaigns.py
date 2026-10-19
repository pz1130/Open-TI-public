import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from opti.api import security
from opti.core.campaign import signature
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.engine import make_sessionmaker
from opti.db.models import Campaign, CampaignMember
from opti.pipeline.campaigns import (
    CampaignConfig,
    CampaignError,
    decide,
    load_campaign_config,
    recompute,
    transition,
)

REPO = Path(__file__).resolve().parents[2]


def test_config_defaults_and_repo_file() -> None:
    cfg = load_campaign_config(REPO / "config" / "campaigns.yaml")
    assert cfg == CampaignConfig()
    assert (cfg.window_days, cfg.max_share, cfg.min_members) == (90, 10, 2)
    assert cfg.signals == ["tls_sha256", "favicon_sha256", "html_sha256", "ip"]
    assert load_campaign_config(REPO / "missing.yaml") == CampaignConfig()


def test_config_rejects_bad_values(tmp_path: Path) -> None:
    path = tmp_path / "campaigns.yaml"
    for text in (
        "max_share: 1\n",
        "min_members: 1\n",
        "signals: []\n",
        "signals: [whois]\n",
        "extra: 1\n",
    ):
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_campaign_config(path)


NOW = datetime(2026, 10, 8, 8, 0, tzinfo=UTC)
IP, IP2, CDN = "93.184.216.34", "93.184.216.35", "104.16.0.1"
HTML = "c" * 64


async def _seed(
    s: AsyncSession, rules: ProjectRules, value: str, *, ip: str | None = None,
    html: str | None = None, tls: str | None = None, status: str = "open",
    created: datetime = NOW, entity_type: str = "domain",
) -> int:  # fmt: skip
    await repo.upsert_project(s, rules)
    entity = await repo.upsert_entity(s, entity_type, value, created)
    enrichment: dict[str, object] = {}
    if ip:
        enrichment["dns"] = {"data": {"a": [ip]}}
    if html:
        enrichment["http_probe"] = {"data": {"html_sha256": html}}
    if tls:
        enrichment["tls"] = {"data": {"sha256": tls}}
    entity.enrichment = enrichment
    up = await repo.upsert_finding(
        s, project_id=rules.project, entity=entity,
        score=Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 20, "domain_risk": 50}),
        match={"domain": value}, source="certstream", now=created,
    )  # fmt: skip
    alert = await repo.open_alert(s, up.finding, Severity.HIGH, created)
    alert.status = status
    await s.flush()
    return up.finding.id


async def _members(s: AsyncSession, campaign_id: int) -> dict[int, str]:
    rows = await s.execute(
        select(CampaignMember.finding_id, CampaignMember.state).where(
            CampaignMember.campaign_id == campaign_id
        )
    )
    return {fid: state for fid, state in rows.all()}


async def _campaigns(s: AsyncSession, state: str) -> list[Campaign]:
    return list(
        (
            await s.scalars(select(Campaign).where(Campaign.state == state).order_by(Campaign.id))
        ).all()
    )


@pytest.mark.db
async def test_recompute_creates_and_keeps_candidates(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    a = await _seed(session, sbr_rules, "sbr-a.top", ip=IP)
    b = await _seed(session, sbr_rules, "sbr-b.top", ip=IP, status="closed")
    await _seed(session, sbr_rules, "sbr-alone.top", ip=IP2)
    result = await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    assert (result.candidates, result.created, result.removed) == (1, 1, 0)
    [candidate] = await _campaigns(session, "candidate")
    assert candidate.signature == signature([a, b])
    assert await _members(session, candidate.id) == {a: "member", b: "member"}
    member = await session.get(CampaignMember, (candidate.id, a))
    assert member is not None
    assert member.signals == [{"kind": "ip", "value": IP, "with_finding": b}]
    # 第二轮：成员集合不变，沿用编号
    again = await recompute(
        session, sbr_rules.project, CampaignConfig(), now=NOW + timedelta(minutes=10)
    )
    assert (again.created, again.removed) == (0, 0)
    assert [c.id for c in await _campaigns(session, "candidate")] == [candidate.id]
    # 新发现连进来：集合变化 → 旧候选删除、新建
    c = await _seed(session, sbr_rules, "sbr-c.top", ip=IP)
    third = await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    assert (third.created, third.removed) == (1, 1)
    [new] = await _campaigns(session, "candidate")
    assert set(await _members(session, new.id)) == {a, b, c}


@pytest.mark.db
async def test_window_and_project_scope(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _seed(session, sbr_rules, "sbr-old1.top", ip=IP, created=NOW - timedelta(days=100))
    await _seed(session, sbr_rules, "sbr-new1.top", ip=IP)
    other = sbr_rules.model_copy(update={"project": "other-project"})
    await _seed(session, other, "sbr-other.top", ip=IP)
    result = await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    assert result.candidates == 0  # 旧的在窗口外，另一项目的不算
    result = await recompute(session, sbr_rules.project, CampaignConfig(window_days=365), now=NOW)
    assert result.candidates == 1


@pytest.mark.db
async def test_dismissed_signature_is_not_regenerated(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    user = await security.create_user(
        session, username="alice", password="x" * 16, roles=["analyst"], now=NOW
    )
    await _seed(session, sbr_rules, "sbr-a.top", ip=IP)
    await _seed(session, sbr_rules, "sbr-b.top", ip=IP)
    await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    [candidate] = await _campaigns(session, "candidate")
    await transition(session, candidate, "dismissed", user_id=user.id, now=NOW)
    result = await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    assert (result.candidates, result.created) == (0, 0)
    await _seed(session, sbr_rules, "sbr-c.top", ip=IP)
    assert (await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)).created == 1


@pytest.mark.db
async def test_recompute_extends_confirmed_without_touching_members(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    user = await security.create_user(
        session, username="alice", password="x" * 16, roles=["analyst"], now=NOW
    )
    a = await _seed(session, sbr_rules, "sbr-a.top", ip=IP)
    b = await _seed(session, sbr_rules, "sbr-b.top", ip=IP)
    await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    [campaign] = await _campaigns(session, "candidate")
    await transition(session, campaign, "confirmed", user_id=user.id, now=NOW)
    assert campaign.confirmed_by == user.id and campaign.confirmed_at == NOW
    await decide(session, campaign, b, "remove", user_id=user.id, now=NOW)
    c = await _seed(session, sbr_rules, "sbr-c.top", ip=IP)
    # a 的 IP 变了：已确认成员不因富化变化被删除
    entity = await repo.upsert_entity(session, "domain", "sbr-a.top", NOW)
    entity.enrichment = {"dns": {"data": {"a": [IP2]}}}
    d = await _seed(session, sbr_rules, "sbr-d.top", ip=IP2)
    await session.flush()
    result = await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    assert result.pending == 1
    # b 被排除：不并回；c 只能经 b（IP）连到 a，a 的 IP 已变 → c 不并入；d 与 a 共用 IP2 → pending
    assert await _members(session, campaign.id) == {a: "member", b: "excluded", d: "pending"}
    assert c not in await _members(session, campaign.id)
    await decide(session, campaign, d, "accept", user_id=user.id, now=NOW)
    assert (await _members(session, campaign.id))[d] == "member"
    with pytest.raises(CampaignError) as e:
        await decide(session, campaign, d, "accept", user_id=user.id, now=NOW)
    assert e.value.status == 409


@pytest.mark.db
async def test_transition_rules_and_reopen(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    user = await security.create_user(
        session, username="alice", password="x" * 16, roles=["analyst"], now=NOW
    )
    a = await _seed(session, sbr_rules, "sbr-a.top", ip=IP)
    b = await _seed(session, sbr_rules, "sbr-b.top", ip=IP)
    await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    [campaign] = await _campaigns(session, "candidate")
    with pytest.raises(CampaignError):
        await decide(session, campaign, a, "remove", user_id=user.id, now=NOW)  # 候选不能决定成员
    await transition(session, campaign, "confirmed", user_id=user.id, now=NOW)
    with pytest.raises(CampaignError) as e:
        await transition(session, campaign, "dismissed", user_id=user.id, now=NOW)
    assert e.value.status == 409
    c = await _seed(session, sbr_rules, "sbr-c.top", ip=IP)
    await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    await decide(session, campaign, b, "remove", user_id=user.id, now=NOW)
    await transition(session, campaign, "candidate", user_id=user.id, now=NOW)
    assert (
        campaign.state == "candidate"
        and campaign.confirmed_at is None
        and campaign.confirmed_by is None
    )
    assert await _members(session, campaign.id) == {
        a: "member",
        c: "member",
    }  # 排除记录删除，待确认转正式
    assert campaign.signature == signature([a, c])


@pytest.mark.db
async def test_confirm_refuses_member_of_another_confirmed_campaign(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    user = await security.create_user(
        session, username="alice", password="x" * 16, roles=["analyst"], now=NOW
    )
    a = await _seed(session, sbr_rules, "sbr-a.top")
    first = Campaign(
        project_id=sbr_rules.project,
        state="confirmed",
        signature="1" * 64,
        created_at=NOW,
        updated_at=NOW,
    )
    second = Campaign(
        project_id=sbr_rules.project,
        state="candidate",
        signature="2" * 64,
        created_at=NOW,
        updated_at=NOW,
    )
    session.add_all([first, second])
    await session.flush()
    session.add_all([
        CampaignMember(campaign_id=first.id, finding_id=a, state="member", added_at=NOW),
        CampaignMember(campaign_id=second.id, finding_id=a, state="member", added_at=NOW),
    ])  # fmt: skip
    await session.flush()
    with pytest.raises(CampaignError) as e:
        await transition(session, second, "confirmed", user_id=user.id, now=NOW)
    assert e.value.status == 409 and second.state == "candidate"


@pytest.mark.db
async def test_acceptance_small_campaign_and_cdn_noise(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    """验收：3 个域名共用独占 IP 与同一模板归为一组；15 个域名共用一个 CDN IP 不被串起来。"""
    gang = [await _seed(session, sbr_rules, f"sbr-gang{i}.top", ip=IP, html=HTML) for i in range(3)]
    for i in range(15):
        await _seed(session, sbr_rules, f"sbr-noise{i}.top", ip=CDN)
    await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    [candidate] = await _campaigns(session, "candidate")
    assert set(await _members(session, candidate.id)) == set(gang)
    assert candidate.ignored == []  # CDN 值只出现在噪声域名上，与本活动无关
    # 让第一个团伙域名也指向 CDN：它仍归在本组，CDN 值出现在忽略说明里
    entity = await repo.upsert_entity(session, "domain", "sbr-gang0.top", NOW)
    entity.enrichment = {
        "dns": {"data": {"a": [IP, CDN]}},
        "http_probe": {"data": {"html_sha256": HTML}},
    }
    await session.flush()
    await recompute(session, sbr_rules.project, CampaignConfig(), now=NOW)
    [candidate] = await _campaigns(session, "candidate")
    assert set(await _members(session, candidate.id)) == set(gang)
    assert candidate.ignored == [{"kind": "ip", "value": CDN, "count": 16}]


@pytest.mark.db
async def test_concurrent_recompute_is_serialised(clean_db: str, sbr_rules: ProjectRules) -> None:
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    try:
        async with sessions.begin() as s:
            for i in range(3):
                await _seed(s, sbr_rules, f"sbr-race{i}.top", ip=IP)

        async def run() -> None:
            async with sessions.begin() as s:
                await recompute(s, sbr_rules.project, CampaignConfig(), now=NOW)

        await asyncio.gather(run(), run())
        async with sessions() as s:
            assert await s.scalar(select(func.count()).select_from(Campaign)) == 1
            assert await s.scalar(select(func.count()).select_from(CampaignMember)) == 3
    finally:
        await engine.dispose()
