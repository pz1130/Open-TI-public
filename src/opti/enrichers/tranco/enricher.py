"""Tranco 排名富化（设计文档 4.5、10.2）：本地 SQLite 索引，查询不联网。"""

from __future__ import annotations

import io
import sqlite3
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import closing
from datetime import date
from pathlib import Path
from typing import Any, ClassVar

from opti.core.domains import parse_domain, to_ascii
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.models import Tier

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


class TrancoIndex:
    def __init__(self, path: Path) -> None:
        self._path = path

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._path)
        conn.execute("CREATE TABLE IF NOT EXISTS ranks (domain TEXT PRIMARY KEY, rank INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        return conn

    @staticmethod
    def _rows(lines: Iterable[str]) -> Iterator[tuple[str, int]]:
        for line in lines:
            rank, _, domain = line.partition(",")
            if rank.strip().isdigit() and domain.strip():
                yield domain.strip().lower(), int(rank)

    def replace(self, lines: Iterable[str], *, list_date: str) -> int:
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM ranks")
            conn.executemany("INSERT OR IGNORE INTO ranks VALUES (?, ?)", self._rows(lines))
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('list_date', ?)", (list_date,))
            return int(conn.execute("SELECT COUNT(*) FROM ranks").fetchone()[0])

    def rank(self, domain: str) -> int | None:
        if not self._path.exists():
            return None
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT rank FROM ranks WHERE domain = ?", (domain.lower(),)
            ).fetchone()
        return int(row[0]) if row else None

    def list_date(self) -> str | None:
        if not self._path.exists():
            return None
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'list_date'").fetchone()
        return str(row[0]) if row else None


async def refresh(
    http: RateLimitedHttpClient,
    index: TrancoIndex,
    *,
    url: str = TRANCO_URL,
    today: date | None = None,
) -> int:
    resp = await http.get(url)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        name = next(n for n in z.namelist() if n.endswith(".csv"))
        lines = z.read(name).decode("utf-8").splitlines()
    return index.replace(lines, list_date=(today or date.today()).isoformat())


class TrancoEnricher(Enricher):
    id: ClassVar[str] = "tranco"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain",)
    cache_ttl_seconds: ClassVar[int] = 24 * 3600

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._index = TrancoIndex(Path(str(self.config.get("db_path", "data/tranco.sqlite"))))

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        list_date = self._index.list_date()
        parts = parse_domain(value)
        if list_date is None or parts is None:
            return {"rank": None, "available": list_date is not None, "list_date": list_date}
        return {
            "rank": self._index.rank(to_ascii(parts.registered)),
            "available": True,
            "list_date": list_date,
        }
