"""把富化结果转换为评分输入（设计文档 9.2）。缺失或格式异常的值视为"未观测"。"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from opti.core.domain_match import DomainMatch
from opti.core.scoring import DomainSignals, UrlSignals
from opti.core.urls import UrlMatch


def _age_days(value: Any, now: datetime) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (now - dt).days


def build_domain_signals(
    match: DomainMatch,
    enrichment: Mapping[str, Mapping[str, Any]],
    *,
    now: datetime | None = None,
    intel_hit: bool | None = None,
) -> DomainSignals:
    dns = enrichment.get("dns") or {}
    rdap = enrichment.get("rdap") or {}
    tranco = enrichment.get("tranco") or {}
    http = enrichment.get("http_probe") or {}
    exists = dns.get("exists")
    resolves = exists if isinstance(exists, bool) else None
    rank = tranco.get("rank")
    status = http.get("status")
    page_ok = http.get("reachable") is True and isinstance(status, int) and status < 400
    return DomainSignals(
        match=match,
        intel_hit=intel_hit,
        age_days=_age_days(rdap.get("registration"), now or datetime.now(UTC)),
        resolves=resolves,
        has_mx=bool(dns.get("mx")) if resolves is not None else None,
        has_login_form=bool(http.get("has_password_field")) if page_ok else None,
        brand_in_content=bool(http.get("brand_terms")) if page_ok else None,
        tranco_rank=rank if isinstance(rank, int) else None,
    )


def build_url_signals(
    match: UrlMatch, enrichment: Mapping[str, Mapping[str, Any]], *, intel_hit: bool | None = None
) -> UrlSignals:
    http = enrichment.get("http_probe") or {}
    status = http.get("status")
    page_ok = http.get("reachable") is True and isinstance(status, int) and status < 400
    return UrlSignals(
        match=match,
        intel_hit=intel_hit,
        has_login_form=bool(http.get("has_password_field")) if page_ok else None,
        brand_in_content=bool(http.get("brand_terms")) if page_ok else None,
    )
