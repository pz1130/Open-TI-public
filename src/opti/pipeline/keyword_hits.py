"""每个域名关键词命中了哪些域名（设计 2026-10-15-domain-keywords）。

按 finding.match.reasons[].token 归属：只算主要命中原因，同形字、诈骗词缀这类辅助原因不算。
先按 (project_id, last_seen) 索引筛出时间窗内的发现，读取量与关键词个数无关。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

PRIMARY_REASONS = (
    "official_embedded",
    "brand_label",
    "brand_combo",
    "brand_substring",
    "brand_fuzzy",
)
WINDOW = timedelta(days=30)


def _match_token(value: str) -> str:
    # 官方域名保留原样；品牌词的原因 token 与 DomainMatcher 一样去掉连字符。
    return value if "." in value else value.replace("-", "")


# reasons 不是数组的历史数据按空数组处理
_HITS = """
FROM finding f
JOIN entity e ON e.id = f.entity_id AND e.type = 'domain'
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(f.match -> 'reasons') = 'array'
         THEN f.match -> 'reasons' ELSE '[]'::jsonb END
) AS r(reason)
WHERE f.project_id = :project
  AND f.last_seen >= :since
  AND r.reason ->> 'reason' = ANY(:reasons)
"""


@dataclass(frozen=True)
class TokenStat:
    findings: int
    last_seen: datetime


@dataclass(frozen=True)
class KeywordHit:
    finding_id: int
    domain: str
    score: int
    severity: str
    last_seen: datetime
    alert_id: int | None
    alert_status: str | None


async def stats(
    session: AsyncSession, project: str, tokens: Sequence[str], *, now: datetime
) -> dict[str, TokenStat]:
    if not tokens:
        return {}
    aliases = {token: _match_token(token) for token in tokens}
    rows = await session.execute(
        text(
            "SELECT r.reason ->> 'token' AS token, count(DISTINCT f.id), max(f.last_seen)"
            + _HITS
            + "AND r.reason ->> 'token' = ANY(:tokens) GROUP BY 1"
        ),
        {
            "project": project,
            "since": now - WINDOW,
            "reasons": list(PRIMARY_REASONS),
            "tokens": list(set(aliases.values())),
        },
    )
    found = {str(t): TokenStat(int(n), seen) for t, n, seen in rows}
    return {token: found[key] for token, key in aliases.items() if key in found}


async def hits(
    session: AsyncSession,
    project: str,
    token: str,
    *,
    now: datetime,
    limit: int,
    offset: int,
) -> tuple[list[KeywordHit], int]:
    params = {
        "project": project,
        "since": now - WINDOW,
        "reasons": list(PRIMARY_REASONS),
        "token": _match_token(token),
    }
    ids = "SELECT DISTINCT f.id" + _HITS + "AND r.reason ->> 'token' = :token"
    total = await session.scalar(text(f"SELECT count(*) FROM ({ids}) AS t"), params)
    rows = await session.execute(
        text(
            f"""
            SELECT f.id, e.value, f.score, f.severity, f.last_seen, a.id, a.status
            FROM finding f
            JOIN entity e ON e.id = f.entity_id
            LEFT JOIN LATERAL (
                SELECT al.id, al.status FROM alert_finding af
                JOIN alert al ON al.id = af.alert_id
                WHERE af.finding_id = f.id
                ORDER BY al.id DESC LIMIT 1
            ) AS a ON true
            WHERE f.id IN ({ids})
            ORDER BY f.last_seen DESC, f.id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {**params, "limit": limit, "offset": offset},
    )
    return [KeywordHit(*row) for row in rows], int(total or 0)
