"""Pagination bounds and empty pages across the long-list APIs."""

from typing import Any

import pytest

pytestmark = pytest.mark.db


@pytest.mark.parametrize(
    "path",
    [
        "alerts",
        "watchlist",
        "documents",
        "reports",
        "takedowns",
        "audit-logs",
        "certificate-monitors",
        "protected-accounts",
    ],
)
async def test_list_page_bounds(path: str, make_user: Any, login: Any) -> None:
    await make_user("all", ("analyst", "auditor"))
    client = await login("all")
    url = f"/api/v1/{path}"
    empty = await client.get(url, params={"page": 2, "limit": 10})
    assert empty.status_code == 200, empty.text
    # Signing in itself creates an audit entry.
    assert empty.json() == {
        "items": [],
        "next_cursor": None,
        "total": 1 if path == "audit-logs" else 0,
    }
    for params in ({"page": 0}, {"page": 1, "limit": 0}, {"page": 1, "cursor": 1}):
        assert (await client.get(url, params=params)).status_code == 422
