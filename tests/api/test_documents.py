from typing import Any

import pytest

from opti.core.documents import document_payload, parse_document
from opti.pipeline import documents

pytestmark = pytest.mark.db


async def _seed(api: Any) -> None:
    async with api.sessions.begin() as session:
        for number, title in enumerate(
            [
                "样本品牌集团发行绿色债券",
                "The Sample Brand approved a loan",
                "A second Sample Brand article",
            ],
            start=1,
        ):
            doc = parse_document(
                document_payload(
                    url=f"https://news.example/{number}",
                    title=title,
                    source_name="Example News",
                    language="zh" if number == 1 else "en",
                )
            )
            await documents.upsert(session, doc, contexts=[title], connector="rss", now=api.clock())


async def test_documents_search_and_pagination(api: Any, make_user: Any, login: Any) -> None:
    await _seed(api)
    await make_user("alice", ("analyst",))
    client = await login("alice")
    result = await client.get("/api/v1/documents", params={"q": "樣本"})
    assert result.status_code == 200 and len(result.json()["items"]) == 1
    assert result.json()["items"][0]["contexts"] == ["样本品牌集团发行绿色债券"]
    first = await client.get("/api/v1/documents", params={"limit": 2})
    assert first.status_code == 200 and len(first.json()["items"]) == 2
    cursor = first.json()["next_cursor"]
    assert cursor is not None
    second = await client.get("/api/v1/documents", params={"limit": 2, "cursor": cursor})
    assert second.status_code == 200 and len(second.json()["items"]) == 1
    assert second.json()["next_cursor"] is None
    numbered = (await client.get("/api/v1/documents", params={"page": 2, "limit": 2})).json()
    assert numbered["items"] == second.json()["items"] and numbered["total"] == 3
    filtered = (
        await client.get(
            "/api/v1/documents",
            params={"page": 2, "limit": 1, "language": "en", "q": "Sample Brand"},
        )
    ).json()
    assert filtered["total"] == 2 and len(filtered["items"]) == 1
    assert (
        await client.get("/api/v1/documents", params={"page": 1, "cursor": cursor})
    ).status_code == 422


async def test_documents_requires_reader_role(api: Any, make_user: Any, login: Any) -> None:
    await make_user("viewer", ("viewer",))
    await make_user("auditor", ("auditor",))
    assert (await (await login("viewer")).get("/api/v1/documents")).status_code == 200
    assert (await (await login("auditor")).get("/api/v1/documents")).status_code == 403
