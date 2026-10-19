from datetime import UTC, datetime

import pytest

from opti.core.documents import (
    MAX_TEXT,
    NEAR_DUP_BITS,
    DocumentError,
    build_search_text,
    document_payload,
    fingerprint,
    from_signed64,
    hamming,
    parse_document,
    select_contexts,
    simhash64,
    to_signed64,
)
from opti.core.text_match import TextHit

ARTICLE = (
    "The Sample Brand approved a new loan to support renewable energy projects in the region on Monday. "
    "Officials said the financing will help build solar and wind capacity over the next five years and create local jobs. "
    "The bank, headquartered in Springfield, has steadily expanded its lending to member countries since it was founded. "
    "Analysts noted that the multilateral lender has been issuing bonds in local currencies to reduce exchange rate risk. "
    "The project includes transmission lines, battery storage and training programmes for engineers in several provinces. "
    "A spokesperson said further approvals are expected later this year as the pipeline of infrastructure projects grows. "
    "Environmental groups welcomed the decision but called for stronger safeguards on land use and community consultation."
)
UNRELATED = (
    "Scammers posted fake loan offers on social media and asked victims to pay a processing fee "
    "before any money was released. Police urged the public to verify offers with official channels. "
) * 3
ZH = (
    "样本品牌集团宣布在春田发行人民币绿色债券，募集资金将用于成员国的可持续基础设施项目。" * 3
)


def test_payload_round_trip() -> None:
    payload = document_payload(
        url="https://News.Example/a?utm_source=x",
        title=" Bank  approves loan ",
        summary="s",
        text="t" * (MAX_TEXT + 10),
        language="en",
        published_at=datetime(2026, 10, 1, 8, tzinfo=UTC),
        source_name="Example News",
        query="q",
    )
    doc = parse_document(payload)
    assert doc.url_normalized == "https://news.example/a"
    assert doc.title == "Bank approves loan" and len(doc.text) == MAX_TEXT
    assert doc.published_at == datetime(2026, 10, 1, 8, tzinfo=UTC)


@pytest.mark.parametrize(
    "doc", [{"url": None, "title": ""}, {"url": "ftp://x.example/a", "title": "t"}, "nope"]
)
def test_invalid_documents(doc: object) -> None:
    with pytest.raises(DocumentError):
        parse_document({"document": doc})


def test_title_only_and_fingerprint() -> None:
    doc = parse_document(document_payload(url=None, title="Headline only"))
    assert doc.url is None and doc.url_normalized is None
    assert fingerprint("Hello   World\n") == fingerprint("hello world")
    assert fingerprint("hello world") != fingerprint("hello there")


def test_simhash_near_duplicates() -> None:
    base = simhash64(ARTICLE)
    edit = simhash64(ARTICLE.replace("five years", "six years"))
    reprint = simhash64(
        "LONDON (Agency) - " + ARTICLE + " Reporting by staff writers; editing by the news desk."
    )
    assert hamming(base, edit) <= NEAR_DUP_BITS
    assert hamming(base, reprint) <= NEAR_DUP_BITS
    assert hamming(base, simhash64(UNRELATED)) > 20
    assert hamming(simhash64(ZH), simhash64(ZH.replace("，", ",").replace("。", "."))) == 0
    assert simhash64("") == 0 and 0 <= base < 2**64
    assert from_signed64(to_signed64(base)) == base


def test_contexts_and_search_text() -> None:
    hits = [
        TextHit("brand", "x", "phrase", "match", 0, 1, " same  context "),
        TextHit("brand", "y", "phrase", "match", 5, 6, "same context"),
    ] + [
        TextHit("brand", "z", "phrase", "match", i, i + 1, f"c{i} " + "w" * 400) for i in range(20)
    ]
    contexts = select_contexts(hits)
    assert contexts[0] == "same context" and len(contexts) == 10
    assert all(len(context) <= 300 for context in contexts)
    assert build_search_text("樣本銀行", "Summary", ["Context"]) == "样本银行 summary context"
