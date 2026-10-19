from opti.core.documents import document_payload, parse_document
from opti.core.scoring import Category, Severity, TextFacts, score_text, text_reasons


def test_document_kind_roundtrip() -> None:
    p = document_payload(
        url="https://otx.alienvault.com/pulse/6510f0c2a1b2c3d4e5f60718", title="t", kind="intel"
    )
    assert p["document"]["kind"] == "intel" and parse_document(p).kind == "intel"
    assert "kind" not in document_payload(url=None, title="t")["document"]  # 不影响 S4-A 的载荷
    assert (
        parse_document({"document": {**p["document"], "kind": "fraud"}}).kind is None
    )  # 只认 intel
    assert parse_document({"document": {**p["document"], "kind": []}}).kind is None


def test_score_text_intel() -> None:
    s = score_text(TextFacts(kind="intel", strong=True, boosters=3, age_days=1, reprints=1))
    assert (s.value, s.severity, s.category) == (55, Severity.MEDIUM, Category.THREAT_INTEL)
    assert s.breakdown["boosters"] == 0
    assert text_reasons(TextFacts("intel", False, 0, 10, 1)) == [
        "brand_abbreviation",
        "threat_report",
        "old_article",
    ]
