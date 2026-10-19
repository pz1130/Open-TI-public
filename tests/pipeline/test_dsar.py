from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api import security
from opti.core.config import ProjectRules
from opti.core.documents import document_payload, parse_document
from opti.core.scoring import Category, Score, Severity
from opti.db import audit, repo
from opti.db.models import Alert, Document, Evidence, ExposedAccount, Feedback, Finding, Report
from opti.pipeline import documents, dsar
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 4, 8, tzinfo=UTC)


async def _world(session: AsyncSession, rules: ProjectRules) -> dict[str, int]:
    await repo.upsert_project(session, rules)
    user = await security.create_user(
        session, username="alice", password="x" * 16, roles=["analyst"], now=NOW
    )
    entity = await repo.upsert_entity(session, "report", "r-1", NOW)
    score = Score(60, Severity.MEDIUM, Category.REPORTED_PHISHING, {"base": 60})
    up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=score,
                                   match={"context": {"description": "Jane Roe 冒充贵行招聘"}}, source="public_report",
                                   now=NOW)  # fmt: skip
    alert = await repo.open_alert(session, up.finding, Severity.MEDIUM, NOW)
    alert.routing = {**alert.routing, "note": "reported by jane roe"}
    session.add_all([
        ExposedAccount(project_id=rules.project, finding_id=up.finding.id, email="jane.roe@sbr.int", source="hibp",
                       first_seen=NOW, last_seen=NOW),
        Feedback(alert_id=alert.id, finding_id=up.finding.id, user_id=user.id, verdict="true_positive",
                 reason="联系 Jane.Roe@sbr.int 核实", created_at=NOW),
        Evidence(finding_id=up.finding.id, alert_id=alert.id, kind="screenshot", object_key="evidence/x.png",
                 sha256="a" * 64, size=1, content_type="image/png", captured_at=NOW, node_id="local", method="test"),
        Report(project_id=rules.project, kind="daily", period_start=NOW - timedelta(days=1), period_end=NOW,
               created_at=NOW, content={"news": [{"title": "Interview with Jane Roe"}]}, sent_sinks=[]),
    ])  # fmt: skip
    await repo.insert_raw_item(session, RawItem(
        connector_id="report_mailbox", source_item_id="m1", fetched_at=NOW, url=None,
        payload={"reporter": "jane.roe@sbr.int", "subject": "phish"}, project_ids=(rules.project,),
    ))  # fmt: skip
    doc = await documents.upsert(
        session, parse_document(document_payload(url="https://news.example/a", title="Bank news")),
        contexts=["CFO Jane Roe said the loan is fake"], connector="rss", now=NOW,
    )  # fmt: skip
    await audit.append(
        session, actor="alice", action="note", now=NOW, detail={"text": "asked Jane Roe"}
    )
    await session.flush()
    return {"finding": up.finding.id, "alert": alert.id, "document": doc.id}


async def test_search_and_erase_by_name(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    ids = await _world(session, sbr_rules)
    subj = dsar.subject(name="  jane   ROE ")
    hits = await dsar.search(session, subj)
    assert hits.counts() == {
        "exposed_accounts": 0, "raw_items": 0, "findings": 1, "documents": 1, "alerts": 1, "reports": 1,
        "feedback": 0, "evidence_review": 1, "audit_log": 1,
    }  # fmt: skip
    assert hits.samples()["findings"] == [ids["finding"]]
    assert await dsar.erase(session, subj) == hits.counts()
    f = await session.get(Finding, ids["finding"])
    assert f is not None and f.match["context"]["description"] == "[REDACTED] 冒充贵行招聘"
    d = await session.get(Document, ids["document"])
    assert (
        d is not None
        and d.contexts == ["CFO [REDACTED] said the loan is fake"]
        and "jane" not in d.search_text
    )
    a = await session.get(Alert, ids["alert"])
    assert a is not None and a.routing["note"] == "reported by [REDACTED]"
    after = (await dsar.search(session, subj)).counts()
    assert (
        after["audit_log"] == 1 and sum(v for k, v in after.items() if k != "audit_log") == 0
    )  # 审计日志不可修改


async def test_search_and_erase_by_email(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _world(session, sbr_rules)
    subj = dsar.subject(email="JANE.ROE@sbr.int")
    counts = (await dsar.search(session, subj)).counts()
    assert counts["exposed_accounts"] == 1 and counts["raw_items"] == 1 and counts["feedback"] == 1
    await dsar.erase(session, subj)
    assert (await session.scalars(select(ExposedAccount))).all() == []
    fb = (await session.scalars(select(Feedback))).one()
    assert fb.reason == "联系 [REDACTED] 核实"
    assert (await dsar.search(session, subj)).counts()["raw_items"] == 0


async def test_dsar_special_characters(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await repo.upsert_project(session, sbr_rules)
    for i, reporter in enumerate(["a_b%c@x.example", "aXbYc@x.example"]):
        await repo.insert_raw_item(session, RawItem(
            connector_id="report_mailbox", source_item_id=f"s{i}", fetched_at=NOW, url=None,
            payload={"reporter": reporter}, project_ids=(sbr_rules.project,),
        ))  # fmt: skip
    hits = await dsar.search(session, dsar.subject(email="a_b%c@x.example"))
    assert len(hits.raw_items) == 1  # % 与 _ 按字面匹配
    odd = dsar.subject(name="O'Brien (CEO) [x]")
    assert (await dsar.search(session, odd)).counts()["findings"] == 0
    assert dsar.scrub({"a": ["o'brien (ceo) [x] said"]}, odd.pattern) == {"a": ["[REDACTED] said"]}


def test_subject_validation() -> None:
    for bad in ({}, {"email": "a@b.c", "name": "Jane"}, {"email": "no-at-sign"}, {"name": " a "}):
        with pytest.raises(dsar.DsarError):
            dsar.subject(**bad)
    a, b = dsar.subject(email="Jane@X.example"), dsar.subject(email="jane@x.example")
    assert a.digest == b.digest and len(a.digest) == 64 and "jane" not in a.digest
