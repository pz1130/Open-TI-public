import io
import zipfile
from datetime import date
from pathlib import Path

import httpx

from opti.core.config import ProjectRules
from opti.enrichers.tranco.enricher import TRANCO_URL, TrancoEnricher, TrancoIndex, refresh
from opti.sdk.testing import make_context, make_http

LINES = ["1,google.com", "2,Facebook.com", "150000,sbrbank.com", "bad line", ""]


def test_index_replace_and_rank(tmp_path: Path) -> None:
    idx = TrancoIndex(tmp_path / "t.sqlite")
    assert idx.list_date() is None
    assert idx.replace(LINES, list_date="2026-10-01") == 3
    assert idx.rank("facebook.com") == 2
    assert idx.rank("unknown.example") is None
    assert idx.list_date() == "2026-10-01"
    assert idx.replace(["1,only.example"], list_date="2026-10-02") == 1
    assert idx.rank("google.com") is None


async def test_refresh_downloads_zip(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "\n".join(LINES))
    payload = buf.getvalue()

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == TRANCO_URL
        return httpx.Response(200, content=payload)

    idx = TrancoIndex(tmp_path / "t.sqlite")
    assert await refresh(make_http(handler), idx, today=date(2026, 10, 2)) == 3
    assert idx.list_date() == "2026-10-02"


async def test_enricher_uses_registered_domain(tmp_path: Path, sbr_rules: ProjectRules) -> None:
    db = tmp_path / "t.sqlite"
    TrancoIndex(db).replace(LINES, list_date="2026-10-01")
    e = TrancoEnricher(make_context(sbr_rules, connector_id="tranco"), {"db_path": str(db)})
    out = await e.enrich("domain", "www.sbrbank.com")
    assert out == {"rank": 150000, "available": True, "list_date": "2026-10-01"}


async def test_enricher_without_list(tmp_path: Path, sbr_rules: ProjectRules) -> None:
    e = TrancoEnricher(
        make_context(sbr_rules, connector_id="tranco"), {"db_path": str(tmp_path / "none.sqlite")}
    )
    assert await e.enrich("domain", "google.com") == {
        "rank": None,
        "available": False,
        "list_date": None,
    }
