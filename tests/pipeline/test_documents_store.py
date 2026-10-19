from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.documents import DocInput, document_payload, parse_document
from opti.db.models import Document
from opti.pipeline import documents

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
ARTICLE = (
    "The Sample Brand approved a new loan to support renewable energy projects in the region on Monday. "
    "Officials said the financing will help build solar and wind capacity over the next five years and create local jobs. "
    "The bank, headquartered in Springfield, has steadily expanded its lending to member countries since it was founded. "
    "Analysts noted that the multilateral lender has been issuing bonds in local currencies to reduce exchange rate risk. "
    "The project includes transmission lines, battery storage and training programmes for engineers in several provinces."
)
OTHER = (
    "Scammers posted fake loan offers on social media and asked victims to pay a processing fee first. "
    * 4
)


def _doc(url: str | None, text: str, title: str = "Bank approves loan") -> DocInput:
    return parse_document(
        document_payload(url=url, title=title, text=text, source_name="Example News")
    )


async def test_same_url_merges_sources(session: AsyncSession) -> None:
    a = await documents.upsert(
        session,
        _doc("https://news.example/a", ARTICLE),
        contexts=["c1"],
        connector="gdelt_doc",
        now=NOW,
    )
    b = await documents.upsert(
        session,
        _doc("https://news.example/a?utm_source=rss", ARTICLE),
        contexts=["c2", "c1"],
        connector="rss",
        now=NOW + timedelta(hours=1),
    )
    assert a.id == b.id and b.connectors == ["gdelt_doc", "rss"]
    assert b.contexts == ["c1", "c2"] and b.cluster_id == b.id
    assert b.last_seen == NOW + timedelta(hours=1)
    assert await session.scalar(select(func.count()).select_from(Document)) == 1


async def test_near_duplicates_share_cluster(session: AsyncSession) -> None:
    a = await documents.upsert(
        session,
        _doc("https://news.example/a", ARTICLE),
        contexts=[],
        connector="gdelt_doc",
        now=NOW,
    )
    reprint = (
        "LONDON (Agency) - " + ARTICLE + " Reporting by staff writers; editing by the news desk."
    )
    b = await documents.upsert(
        session, _doc("https://mirror.example/b", reprint), contexts=[], connector="rss", now=NOW
    )
    c = await documents.upsert(
        session,
        _doc("https://other.example/c", OTHER, "Scam warning"),
        contexts=[],
        connector="rss",
        now=NOW,
    )
    assert b.cluster_id == a.id and c.cluster_id == c.id
    assert await documents.cluster_size(session, a.id) == 2
    d = await documents.upsert(
        session,
        _doc("https://late.example/d", ARTICLE),
        contexts=[],
        connector="rss",
        now=NOW + timedelta(days=40),
    )
    assert d.cluster_id == d.id


async def test_title_only_documents_dedupe_by_content(session: AsyncSession) -> None:
    a = await documents.upsert(
        session, _doc(None, "", "Headline only"), contexts=[], connector="rss", now=NOW
    )
    b = await documents.upsert(
        session, _doc(None, "", "Headline only"), contexts=[], connector="gdelt_doc", now=NOW
    )
    assert a.id == b.id


async def test_search_chinese_and_traditional(session: AsyncSession) -> None:
    zh = await documents.upsert(
        session,
        _doc("https://cn.example/1", "", "样本品牌集团发行绿色债券"),
        contexts=["样本品牌在春田发行人民币绿色债券"],
        connector="rss",
        now=NOW,
    )
    en = await documents.upsert(
        session,
        _doc("https://news.example/a", ARTICLE),
        contexts=["renewable energy projects"],
        connector="rss",
        now=NOW,
    )
    assert [row.id for row in await documents.search(session, "樣本")] == [zh.id]
    assert [row.id for row in await documents.search(session, "绿色")] == [zh.id]
    assert [row.id for row in await documents.search(session, "Renewable Energy")] == [en.id]
    assert await documents.search(session, "%") == []
    assert {row.id for row in await documents.search(session, None)} == {zh.id, en.id}
    assert [row.id for row in await documents.search(session, None, cursor=en.id)] == [zh.id]


async def test_purge(session: AsyncSession) -> None:
    await documents.upsert(
        session,
        _doc("https://news.example/a", ARTICLE),
        contexts=[],
        connector="rss",
        now=NOW - timedelta(days=400),
    )
    await documents.upsert(
        session, _doc("https://news.example/b", OTHER), contexts=[], connector="rss", now=NOW
    )
    assert await documents.purge(session, NOW - timedelta(days=365)) == 1
