"""阻断列表（设计文档 12）：最近一次研判为真实威胁的仿冒域名与钓鱼 URL，供邮件网关、DNS 防火墙、代理拉取。

排除官方域名、已知合法相似方及其子域、生效中的抑制规则；URL 的主机不进入域名列表或 RPZ（共享托管会误伤）。
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.domains import parse_domain, to_ascii
from opti.db.models import Alert, AlertFinding, Entity, Feedback, Finding
from opti.pipeline import suppression
from opti.takedown.hosting import alert_host

CSV_HEADER = ("type", "value", "category", "severity", "first_seen", "last_seen", "alert_id")


@dataclass(frozen=True)
class Entry:
    type: str  # domain / url
    value: str
    category: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    alert_id: int


def protected_host(host: str, rules: ProjectRules) -> bool:
    """官方域名、已知合法相似方或其子域不能作为威胁指标。"""
    h = _ascii(host) or ""
    for d in (*rules.domains.official, *rules.domains.known_lookalikes):
        d = _ascii(d) or ""
        if h == d or h.endswith("." + d):
            return True
    return False


async def confirmed_entries(
    session: AsyncSession, rules: ProjectRules, *, now: datetime, days: int
) -> list[Entry]:
    rows = (
        await session.execute(
            select(Entity, Finding, Alert)
            .join(Finding, Finding.entity_id == Entity.id)
            .join(AlertFinding, AlertFinding.finding_id == Finding.id)
            .join(Alert, Alert.id == AlertFinding.alert_id)
            .where(
                Finding.project_id == rules.project,
                Alert.triage_verdict.is_not(None),
                Finding.last_seen >= now - timedelta(days=days),
                Entity.type.in_(("domain", "url")),
            )
            .order_by(
                func.coalesce(
                    select(func.max(Feedback.created_at))
                    .where(Feedback.alert_id == Alert.id)
                    .correlate(Alert)
                    .scalar_subquery(),
                    Alert.created_at,
                ).desc(),
                Alert.id.desc(),
            )
        )
    ).all()
    seen: set[int] = set()
    out: list[Entry] = []
    for entity, finding, alert in rows:
        if entity.id in seen:
            continue
        seen.add(entity.id)  # 只看最近一次研判：后来改判为误报的不再导出
        if alert.triage_verdict != "true_positive":
            continue
        host = alert_host(entity.type, entity.value)
        if not host or protected_host(host, rules):
            continue
        parts = parse_domain(host)
        registered = parts.registered if parts is not None else host
        if await suppression.find_active(
            session, rules.project, domain=host, registered=registered, now=now
        ):
            continue
        out.append(
            Entry(entity.type, entity.value, finding.category, finding.severity, finding.first_seen, finding.last_seen, alert.id)
        )  # fmt: skip
    return out


def _ascii(host: str) -> str | None:
    try:
        value = to_ascii(host.lower().rstrip("."))
        if len(value) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        ):
            return None
        return value
    except UnicodeError:
        return None


def _domains(entries: Sequence[Entry]) -> list[str]:
    return sorted({a for e in entries if e.type == "domain" and (a := _ascii(e.value))})


def to_txt(entries: Sequence[Entry], kind: str = "domain") -> str:
    values = (
        sorted({e.value for e in entries if e.type == "url"})
        if kind == "url"
        else _domains(entries)
    )
    return "".join(f"{v}\n" for v in values)


def _cell(value: str) -> str:
    """防止表格软件把单元格当公式执行。"""
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def to_csv(entries: Sequence[Entry]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    for e in sorted(entries, key=lambda x: (x.type, x.value)):
        writer.writerow(
            [
                e.type,
                _cell((_ascii(e.value) or "") if e.type == "domain" else e.value),
                e.category,
                e.severity,
                e.first_seen.isoformat(),
                e.last_seen.isoformat(),
                e.alert_id,
            ]
        )
    return buf.getvalue()


def to_rpz(entries: Sequence[Entry], now: datetime) -> str:
    """DNS 响应策略区（RPZ）：域名及其子域返回 NXDOMAIN（CNAME .）。序列号为 Unix 秒。"""
    lines = [
        "$TTL 300",
        f"@ IN SOA localhost. hostmaster.localhost. ({int(now.timestamp())} 3600 600 86400 300)",
        "@ IN NS localhost.",
    ]
    for d in _domains(entries):
        lines += [f"{d} CNAME .", f"*.{d} CNAME ."]
    return "\n".join(lines) + "\n"
