"""自有域名证书监控的范围校验与有效期判断。"""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import idna

from opti.core import policy
from opti.core.domains import normalize_domain


def certificate_domain(raw: str) -> str:
    if "*" in raw:
        raise ValueError("请输入完整域名，不能使用通配符")
    domain = normalize_domain(raw)
    if domain is None:
        raise ValueError("域名格式无效")
    try:
        return idna.encode(domain, uts46=True, std3_rules=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError("域名格式无效") from exc


def in_scope(domain: str, root: str) -> bool:
    return domain == root or domain.endswith("." + root)


# CT 历史里的主机常已下线：连续读取失败这么久后不再检查，避免失败主机越积越多


def retired(
    domain: str, failing_since: datetime | None, root: str, known: Iterable[str], now: datetime
) -> bool:
    """从 CT 发现的主机连续失败满 30 天即停查；根域名与手动补充的主机始终检查。"""
    if domain == root or domain in known or failing_since is None:
        return False
    return failing_since <= now - timedelta(days=policy.current().certificates.retire_after_days)


def certificate_expiry(
    data: dict[str, Any], now: datetime, warn_days: int
) -> tuple[str, datetime | None, int | None, int]:
    if data.get("error") or not data.get("present"):
        return "error", None, None, 0
    try:
        end = datetime.fromisoformat(str(data["not_after"]).replace("Z", "+00:00"))
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
    except (KeyError, ValueError):
        return "error", None, None, 0
    remaining = end - now
    days = math.floor(remaining.total_seconds() / 86400)
    if remaining <= timedelta(0):
        return "expired", end, days, 90
    if remaining <= timedelta(days=warn_days):
        return (
            "expiring",
            end,
            days,
            70
            if remaining <= timedelta(days=policy.current().certificates.urgent_expiry_days)
            else 50,
        )
    return "healthy", end, days, 0
