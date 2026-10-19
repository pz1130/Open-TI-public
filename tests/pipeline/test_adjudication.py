from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from opti.core import policy
from opti.core.adjudication import AdjudicationError, Assessment, LlmConfig, PublicInput
from opti.core.code_adjudication import CodeAssessment, CodeInput
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, severity_for
from opti.db import repo
from opti.db.engine import make_sessionmaker
from opti.db.models import Adjudication, Alert, AuditLog, Finding
from opti.llm import Answer
from opti.organization import Organization
from opti.pipeline import adjudication

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
CFG = LlmConfig(max_attempts=2, max_wait_minutes=30)
ORG = Organization(name="Sample Brand", short_name="SBR")
MATCH = {
    "kind": "press", "strong": False, "terms": ["SBR"],
    "document": {"id": None, "url": "https://news.example/a", "title": "SBR faces lawsuit", "source_name": "Example News"},
    "contexts": ["The SBR, the ORBIT lender based in Springfield, faces a lawsuit"],
    "reasons": [{"reason": "brand_abbreviation"}, {"reason": "press_terms"}],
}  # fmt: skip


class FakeAdjudicator:
    backend = "fake"
    model = "fake-1"
    provider = "Fake"

    def __init__(self, verdict: str = "yes", fail: bool = False) -> None:
        self.verdict, self.fail = verdict, fail
        self.inputs: list[PublicInput] = []

    async def answer(self, inp: PublicInput) -> Answer:
        self.inputs.append(inp)
        if self.fail:
            raise AdjudicationError("模型接口调用失败（429）")
        result = Assessment(
            self.verdict, "negative_press", 0.8, "ORBIT lender in Springfield.", "样本品牌面临诉讼"
        )
        return Answer(result, "fake-backup", "fake-2", "Fake Backup")  # 实际作答的是备用


@pytest.fixture
async def sessions(clean_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(clean_db)
    yield make_sessionmaker(engine)
    await engine.dispose()


async def _finding(
    sessions: async_sessionmaker[AsyncSession], rules: ProjectRules, *, hold: bool = True
) -> int:
    async with sessions() as s, s.begin():
        await repo.upsert_project(s, rules)
        entity = await repo.upsert_entity(s, "document", "cluster:1", NOW)
        score = Score(
            50,
            severity_for(50),
            Category.NEGATIVE_PRESS,
            {"base": 35, "match_strength": 5, "boosters": 10},
        )
        up = await repo.upsert_finding(s, project_id=rules.project, entity=entity, score=score, match=MATCH,
                                       source="gdelt_doc", now=NOW)  # fmt: skip
        await adjudication.request(s, up.finding, hold=score.severity if hold else None, now=NOW)
        await adjudication.request(
            s, up.finding, hold=None, now=NOW
        )  # 同一 Finding 只保留一条待处理请求
        return up.finding.id


async def _run(sessions: async_sessionmaker[AsyncSession], rules: ProjectRules, adj: FakeAdjudicator | None,
               *, cfg: LlmConfig | None = CFG, now: datetime = NOW) -> list[int]:  # fmt: skip
    return await adjudication.run_pending(
        sessions, adj, cfg=cfg, rules=rules, organization=ORG, clock=lambda: now
    )


async def test_yes_opens_held_alert(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _finding(sessions, sbr_rules)
    fake = FakeAdjudicator("yes")
    [alert_id] = await _run(sessions, sbr_rules, fake)
    assert (
        fake.inputs[0].organization == "Sample Brand"
        and "ORBIT" in fake.inputs[0].contexts[0]
    )
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert (
            f is not None
            and f.score == 60
            and f.score_breakdown["llm"] == 10
            and f.severity == "medium"
        )
        assert f.match["llm"]["verdict"] == "yes" and f.match["llm"]["model"] == "fake-2"
        alert = await s.get(Alert, alert_id)
        assert alert is not None and alert.severity == "medium"
        [row] = (await s.scalars(select(Adjudication))).all()
        assert (row.status, row.verdict, row.attempts, row.backend, row.model) == (
            "done",
            "yes",
            1,
            "fake-backup",
            "fake-2",
        )
        assert (
            row.input_sha256 == fake.inputs[0].digest()
            and row.output["summary"] == "样本品牌面临诉讼"
        )
        log = (await s.scalars(select(AuditLog).where(AuditLog.action == "llm.assess"))).one()
        assert (
            log.actor == "system:llm"
            and log.detail["verdict"] == "yes"
            and log.target_id == str(fid)
            and log.detail["provider"] == "Fake Backup"
        )
    assert await _run(sessions, sbr_rules, fake) == [] and len(fake.inputs) == 1  # 处理过的不再研判


@pytest.mark.parametrize("enabled", [True, False])
async def test_inactive_project_is_not_assessed_or_released(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules, enabled: bool
) -> None:
    inactive = await _finding(sessions, sbr_rules.model_copy(update={"project": "inactive"}))
    active = await _finding(sessions, sbr_rules)
    fake = FakeAdjudicator() if enabled else None
    alerts = await _run(sessions, sbr_rules, fake, cfg=CFG if enabled else None)
    assert len(alerts) == 1
    async with sessions() as s:
        pending = await s.scalar(select(Adjudication).where(Adjudication.finding_id == inactive))
        assert pending.status == "pending" and pending.attempts == 0
        assert (
            await s.scalar(select(Alert.id).where(Alert.project_id == sbr_rules.project))
            is not None
        )
        assert (await s.get(Finding, active)).project_id == sbr_rules.project


async def test_no_lowers_score_without_alert(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _finding(sessions, sbr_rules)
    assert await _run(sessions, sbr_rules, FakeAdjudicator("no")) == []
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert f is not None and f.score == 20 and f.severity == "low"
        assert (await s.scalars(select(Alert))).all() == []


async def test_unheld_request_only_rescores(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _finding(sessions, sbr_rules, hold=False)
    assert (
        await _run(sessions, sbr_rules, FakeAdjudicator("yes")) == []
    )  # Medium → Medium：没有暂缓、也没有升级
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert f is not None and f.score == 60


async def test_failures_release_held_alert(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    await _finding(sessions, sbr_rules)
    failing = FakeAdjudicator(fail=True)
    assert await _run(sessions, sbr_rules, failing) == []  # 第 1 次失败：保留排队
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        assert row.status == "pending" and row.attempts == 1 and "429" in (row.error or "")
    [alert_id] = await _run(sessions, sbr_rules, failing)  # 达到 max_attempts：按规则分数放行
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        alert = await s.get(Alert, alert_id)
        failures = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "llm.assess_failed"))
        ).all()
        assert row.status == "failed" and alert is not None and alert.severity == "medium"
        assert (row.backend, row.model, row.prompt_version) == ("fake", "fake-1", "s4d-1")
        assert len(failures) == 2 and all(
            x.detail["input_sha256"] == row.input_sha256 and x.detail["provider"] == "Fake"
            for x in failures
        )


async def test_wait_timeout_releases(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    await _finding(sessions, sbr_rules)
    fake = FakeAdjudicator("no")
    assert len(await _run(sessions, sbr_rules, fake, now=NOW + timedelta(minutes=31))) == 1
    assert fake.inputs == []  # 超时的直接放行，不再调用模型


async def test_disabled_backend_releases_queue(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    await _finding(sessions, sbr_rules)
    assert len(await _run(sessions, sbr_rules, None, cfg=None)) == 1
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        assert row.status == "failed" and "关闭" in (row.error or "")


async def test_invalid_queued_input_releases_held_alert(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _finding(sessions, sbr_rules)
    async with sessions() as s, s.begin():
        finding = await s.get(Finding, fid)
        assert finding is not None
        finding.category = Category.PHISHING_SITE.value
    [alert_id] = await _run(sessions, sbr_rules, FakeAdjudicator())
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        assert row.status == "failed"
        assert await s.get(Alert, alert_id) is not None


CODE_CFG = LlmConfig(max_attempts=2, max_wait_minutes=30, code_enabled=True)
SECRETS = [
    {"rule": "generic-api-key", "file": "src/settings.py", "line": 3, "commit": "c" * 40,
     "date": "2026-09-20T00:00:00Z", "prefix": "abcd", "fingerprint": "a" * 64, "length": 32,
     "context": ["API_KEY = 'abcd…[REDACTED:12345678]'"]},
    {"rule": "generic-api-key", "file": "tests/fixtures.py", "line": 1, "commit": "c" * 40,
     "date": "2026-09-01T00:00:00Z", "prefix": "test", "fingerprint": "b" * 64, "length": 32,
     "context": ["KEY = 'test…[REDACTED:87654321]'  # fake"]},
]  # fmt: skip
CODE_MATCH = {
    "repo": "dev2/deploy",
    "hits": [],
    "scan": {"secrets": SECRETS, "repo_meta": {"owner": "dev2"}},
}


class FakeCodeAdjudicator(FakeAdjudicator):
    def __init__(self, verdict: str = "real", relation: str = "org") -> None:
        super().__init__()
        self.verdict, self.relation = verdict, relation
        self.code_inputs: list[CodeInput] = []

    async def answer(self, inp: PublicInput | CodeInput) -> Answer:  # type: ignore[override]
        assert isinstance(inp, CodeInput)
        self.code_inputs.append(inp)
        result = CodeAssessment(
            tuple((s.ref, self.verdict) for s in inp.secrets), self.relation, 0.7, "r", "部署脚本"
        )
        return Answer(result, "fake", "fake-1", "Fake")


async def _code_finding(sessions: async_sessionmaker[AsyncSession], rules: ProjectRules) -> int:
    """规则 55 分（Medium）；明细里带着上一轮的模型因子，重算时必须忽略。"""
    async with sessions() as s, s.begin():
        await repo.upsert_project(s, rules)
        entity = await repo.upsert_entity(s, "repo", "github.com/dev2/deploy", NOW)
        breakdown = {
            "base": 45,
            "secret_kind": 10,
            "llm_secret": -15,
            "llm_relation": -10,
            "llm_floor": 10,
        }
        score = Score(40, severity_for(40), Category.SECRET_LEAK, breakdown)
        up = await repo.upsert_finding(s, project_id=rules.project, entity=entity, score=score,
                                       match=CODE_MATCH, source="secret_scan", now=NOW)  # fmt: skip
        await adjudication.request(s, up.finding, hold=score.severity, now=NOW)
        return up.finding.id


async def test_code_verdict_raises_and_opens_held_alert(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _code_finding(sessions, sbr_rules)
    fake = FakeCodeAdjudicator("real", "org")
    [alert_id] = await _run(sessions, sbr_rules, fake, cfg=CODE_CFG)
    assert [s.file for s in fake.code_inputs[0].secrets] == ["src/settings.py", "tests/fixtures.py"]
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert f is not None and f.score == 75 and f.severity == "high"
        assert f.score_breakdown == {
            "base": 45,
            "secret_kind": 10,
            "llm_secret": 10,
            "llm_relation": 10,
        }
        assert f.match["llm_code"]["secrets"] == [
            {"fingerprint": "a" * 64, "verdict": "real"},
            {"fingerprint": "b" * 64, "verdict": "real"},
        ]
        assert (
            f.match["llm_code"]["relation"] == "org"
            and f.match["llm_code"]["prompt_version"] == "code-1"
        )
        assert "llm" not in f.match
        alert = await s.get(Alert, alert_id)
        assert alert is not None and alert.severity == "high"
        row = (await s.scalars(select(Adjudication))).one()
        assert (row.status, row.verdict, row.prompt_version) == ("done", "real", "code-1")
        assert row.input_sha256 == fake.code_inputs[0].digest() and row.output["relation"] == "org"
        log = (await s.scalars(select(AuditLog).where(AuditLog.action == "llm.assess"))).one()
        assert log.detail["relation"] == "org" and log.detail["prompt_version"] == "code-1"


async def test_code_example_keeps_alert_at_alert_line(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _code_finding(sessions, sbr_rules)
    [alert_id] = await _run(
        sessions, sbr_rules, FakeCodeAdjudicator("example", "unrelated"), cfg=CODE_CFG
    )
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert f is not None and f.score == 40 and f.severity == "medium"
        assert f.score_breakdown["llm_floor"] == 10
        alert = await s.get(Alert, alert_id)
        assert alert is not None and alert.severity == "medium"  # 不压掉告警


async def test_code_switch_off_releases_queued_secret(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    await _code_finding(sessions, sbr_rules)
    fake = FakeCodeAdjudicator()
    [alert_id] = await _run(sessions, sbr_rules, fake, cfg=CFG)  # 总开关开、代码开关关
    assert fake.code_inputs == []
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        assert row.status == "failed" and "代码研判已关闭" in (row.error or "")
        alert = await s.get(Alert, alert_id)
        assert alert is not None and alert.severity == "medium"


async def test_code_verdict_for_changed_finding_is_dropped(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _code_finding(sessions, sbr_rules)
    async with sessions() as s, s.begin():
        row = (await s.scalars(select(Adjudication))).one()
        finding = await s.get(Finding, fid)
        assert finding is not None
        finding.category = Category.DATA_LEAK.value  # 重扫后已经没有密钥
        answer = Answer(
            CodeAssessment((("S1", "real"),), "org", 0.9, "r", "s"), "fake", "fake-1", "Fake"
        )
        [alert_id] = await adjudication.apply(s, row.id, answer, now=NOW, refs={"S1": "a" * 64})
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        f = await s.get(Finding, fid)
        assert row.status == "failed" and f is not None and "llm_code" not in f.match
        assert await s.get(Alert, alert_id) is not None


async def test_code_verdict_for_replaced_secrets_is_requeued(
    sessions: async_sessionmaker[AsyncSession], sbr_rules: ProjectRules
) -> None:
    fid = await _code_finding(sessions, sbr_rules)
    async with sessions() as s, s.begin():
        row = (await s.scalars(select(Adjudication))).one()
        finding = await s.get(Finding, fid)
        assert finding is not None
        fresh = [{**SECRETS[0], "fingerprint": "c" * 64, "file": "deploy/prod.env"}]
        finding.match = {
            **finding.match,
            "scan": {**finding.match["scan"], "secrets": fresh},
        }  # 研判途中重扫
        answer = Answer(
            CodeAssessment((("S1", "example"),), "unrelated", 0.9, "r", "s"),
            "fake",
            "fake-1",
            "Fake",
        )
        assert (
            await adjudication.apply(
                s, row.id, answer, now=NOW, refs={"S1": "a" * 64, "S2": "b" * 64}
            )
            == []
        )
    async with sessions() as s:
        row = (await s.scalars(select(Adjudication))).one()
        f = await s.get(Finding, fid)
        assert row.status == "pending" and row.leased_until is None and f is not None
        assert "llm_code" not in f.match  # 旧结论不写入
    fake = FakeCodeAdjudicator("real", "org")
    [alert_id] = await _run(sessions, sbr_rules, fake, cfg=CODE_CFG)  # 下一轮按新密钥重判
    assert [s.file for s in fake.code_inputs[0].secrets] == ["deploy/prod.env"]
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert f is not None and f.match["llm_code"]["secrets"] == [
            {"fingerprint": "c" * 64, "verdict": "real"}
        ]
        assert await s.get(Alert, alert_id) is not None


async def test_rescored_finding_respects_configured_alert_line(
    sessions: async_sessionmaker[AsyncSession],
    sbr_rules: ProjectRules,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        policy,
        "_current",
        policy.OperationsConfig.model_validate({"risk": {"alert_from": "critical"}}),
    )
    fid = await _code_finding(sessions, sbr_rules)
    async with sessions() as s, s.begin():
        row = (await s.scalars(select(Adjudication))).one()
        row.held_severity = None  # 规则分 Medium 低于告警线：排队但不暂缓
    assert await _run(sessions, sbr_rules, FakeCodeAdjudicator("real", "org"), cfg=CODE_CFG) == []
    async with sessions() as s:
        f = await s.get(Finding, fid)
        assert f is not None and f.severity == "high"  # 升到 High，仍低于 Critical：不开告警
        assert (await s.scalars(select(Alert))).all() == []
