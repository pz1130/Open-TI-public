import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.adjudication import LlmConfig
from opti.core.config import ProjectRules
from opti.core.documents import document_payload
from opti.db.models import Adjudication, Alert, Document, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.llm_runtime import StaticLlm
from opti.pipeline.processor import Processor
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
FILLER = " ".join(
    f"Paragraph {i} discusses regional infrastructure, trade corridors and climate finance."
    for i in range(30)
)
MARKER = "ZEBRA-MARKER-UNRELATED-SENTENCE"


def _item(
    rules: ProjectRules,
    url: str,
    text: str,
    title: str = "Regional finance news",
    *,
    published: datetime | None = None,
    connector: str = "gdelt_doc",
    language: str | None = "en",
) -> RawItem:
    payload = document_payload(
        url=url,
        title=title,
        text=text,
        language=language,
        source_name="Example News",
        published_at=published or NOW - timedelta(days=1),
    )
    return RawItem(
        connector_id=connector,
        source_item_id=url,
        fetched_at=NOW,
        url=url,
        payload=payload,
        project_ids=(rules.project,),
    )


def _processor(rules: ProjectRules) -> Processor:
    return Processor(rules, EnrichmentService({}), clock=lambda: NOW)


async def test_mention_is_stored_without_alert(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    text = f"{FILLER} The Sample Brand approved a loan for renewable energy. {FILLER}"
    result = await _processor(sbr_rules).process(
        session, _item(sbr_rules, "https://news.example/a", text)
    )
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "brand_mention"
    assert finding.severity == "low" and result.alerts == []
    assert finding.match["terms"] == ["Sample Brand"]
    assert finding.match["reprints"] == 1
    doc = (await session.scalars(select(Document))).one()
    assert any("Sample Brand" in context for context in doc.contexts)


async def test_full_text_is_not_stored(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    text = f"{FILLER} The Sample Brand approved a loan. {FILLER} {MARKER} {FILLER}"
    result = await _processor(sbr_rules).process(
        session, _item(sbr_rules, "https://news.example/a", text)
    )
    raw = (await session.scalars(select(RawItemRow))).one()
    doc = (await session.scalars(select(Document))).one()
    finding = await session.get(Finding, result.findings[0])
    blobs = [
        json.dumps(raw.payload),
        doc.title,
        doc.snippet,
        " ".join(doc.contexts),
        doc.search_text,
        json.dumps(finding.match if finding else {}),
    ]
    assert all(MARKER not in blob and MARKER.lower() not in blob for blob in blobs)
    assert raw.payload["document"]["text"] == ""
    assert raw.payload["document"]["text_length"] == len(text)


async def test_missing_source_language_is_detected_after_match(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    text = "样本品牌宣布在成员国扩大绿色基础设施融资，支持可持续发展项目。" * 3
    result = await _processor(sbr_rules).process(
        session, _item(sbr_rules, "https://news.example/zh", text, language=None)
    )
    assert len(result.findings) == 1
    row = (await session.scalars(select(Document))).one()
    raw = (await session.scalars(select(RawItemRow))).one()
    assert row.language == "zh"
    assert raw.payload["document"]["text"] == ""
    assert raw.payload["document"]["language"] is None


async def test_source_language_is_preserved_and_detection_failure_does_not_block(
    session: AsyncSession, sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "The Sample Brand approved a loan for renewable energy projects in South Africa."

    def broken(_text: str) -> str:
        raise RuntimeError("detector unavailable")

    monkeypatch.setattr("opti.pipeline.processor.detect_language", broken)
    processor = _processor(sbr_rules)
    first = await processor.process(
        session, _item(sbr_rules, "https://news.example/en", text, language="en")
    )
    second = await processor.process(
        session, _item(sbr_rules, "https://news.example/unknown", text, language=None)
    )
    assert len(first.findings) == len(second.findings) == 1
    rows = (await session.scalars(select(Document).order_by(Document.id))).all()
    assert [row.language for row in rows] == ["en", None]


async def test_fraud_and_press(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    processor = _processor(sbr_rules)
    fraud = await processor.process(
        session,
        _item(
            sbr_rules,
            "https://scam.example/1",
            "Fake Sample Brand loan offer: pay a processing fee to receive the money.",
        ),
    )
    finding = await session.get(Finding, fraud.findings[0])
    assert finding is not None and finding.category == "fraud_scam"
    assert finding.severity == "high" and len(fraud.alerts) == 1
    assert finding.match["boosters"] == ["loan offer", "processing fee"]
    press = await processor.process(
        session,
        _item(
            sbr_rules,
            "https://news.example/p",
            "The Sample Brand faces a lawsuit over a contract.",
        ),
    )
    finding = await session.get(Finding, press.findings[0])
    assert finding is not None and finding.category == "negative_press"
    assert finding.severity == "medium" and len(press.alerts) == 1


async def test_unmatched_documents_store_nothing(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    processor = _processor(sbr_rules)
    for index, text in enumerate(
        [
            FILLER,
            "SBR Bank PLC reported a rise in quarterly profit in Colombo.",
            "MySQL SBR Cluster 8.0 adds new replication features.",
        ]
    ):
        result = await processor.process(
            session, _item(sbr_rules, f"https://n.example/{index}", text)
        )
        assert result.findings == []
    assert await session.scalar(select(func.count()).select_from(Document)) == 0


async def test_reprints_alert_once(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    processor = _processor(sbr_rules)
    story = f"{FILLER} Fake Sample Brand loan offer asks for a processing fee. {FILLER}"
    first = await processor.process(session, _item(sbr_rules, "https://scam.example/1", story))
    second = await processor.process(
        session,
        _item(
            sbr_rules,
            "https://mirror.example/x",
            "MIRROR - " + story + " Shared by readers.",
            connector="rss",
        ),
    )
    assert len(first.alerts) == 1 and second.alerts == []
    assert first.findings == second.findings
    finding = await session.get(Finding, first.findings[0])
    assert finding is not None and finding.match["reprints"] == 2
    assert len(finding.match["documents"]) == 2
    assert set(finding.sources) == {"gdelt_doc", "rss"}
    assert await session.scalar(select(func.count()).select_from(Alert)) == 1


async def test_old_article_is_lowered(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    result = await _processor(sbr_rules).process(
        session,
        _item(
            sbr_rules,
            "https://news.example/old",
            "The Sample Brand faces a lawsuit.",
            published=NOW - timedelta(days=30),
        ),
    )
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.score_breakdown["recency"] == -10
    assert {r["reason"] for r in finding.match["reasons"]} >= {"old_article", "press_terms"}


async def test_threat_intel_pulse(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    url = "https://otx.alienvault.com/pulse/6510f0c2a1b2c3d4e5f60718"
    payload = document_payload(url=url, title="Spear-phishing campaign against development banks",
                               summary="Lures impersonate the Sample Brand and mention a lawsuit.",
                               text="Tags: phishing", source_name="AlienVault OTX",
                               published_at=NOW - timedelta(days=1), kind="intel")  # fmt: skip
    item = RawItem(connector_id="otx", source_item_id="6510f0c2a1b2c3d4e5f60718#1", fetched_at=NOW, url=url,
                   payload=payload, project_ids=(sbr_rules.project,))  # fmt: skip
    result = await _processor(sbr_rules).process(session, item)
    f = await session.get(Finding, result.findings[0])
    # 含舆情增强词（lawsuit）也按威胁情报处理；40 + 15 = 55
    assert f is not None and f.category == "threat_intel" and f.severity == "medium"
    assert f.score == 55
    assert "threat_report" in {r["reason"] for r in f.match["reasons"]} and len(result.alerts) == 1


async def test_gray_zone_waits_for_adjudication(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    llm = StaticLlm(LlmConfig())
    proc = Processor(sbr_rules, EnrichmentService({}), clock=lambda: NOW, llm=llm)
    sentence = "The SBR, the ORBIT lender based in Springfield, faces a lawsuit over a contract."
    story = f"{FILLER} {sentence} {FILLER}"
    first = await proc.process(session, _item(sbr_rules, "https://news.example/n", story))
    assert first.alerts == []  # 只命中缩写（35 + 5 + 10 = 50）：先等研判
    row = (await session.scalars(select(Adjudication))).one()
    assert row.status == "pending" and row.held_severity == "medium"
    finding = await session.get(Finding, first.findings[0])
    assert finding is not None
    finding.match = {**finding.match, "llm": {"verdict": "yes"}}  # 模拟研判已完成
    await session.flush()
    again = await proc.process(
        session, _item(sbr_rules, "https://mirror.example/n", "MIRROR - " + story, connector="rss")
    )
    assert again.findings == first.findings
    updated = await session.get(Finding, again.findings[0])
    assert (
        updated is not None
        and updated.score_breakdown["llm"] == 10
        and updated.match["llm"]["verdict"] == "yes"
    )
    assert len((await session.scalars(select(Adjudication))).all()) == 1  # 已有结论的聚类不再排队
    plain = await _processor(sbr_rules).process(session, _item(sbr_rules, "https://news.example/p",
        "The SBR, the ORBIT lender in Springfield, faces a lawsuit."))  # fmt: skip
    assert len(plain.alerts) == 1  # 未启用研判时照常告警
