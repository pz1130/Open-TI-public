"""解析 certstream（certstream-server-go lite 流）消息。格式异常的消息一律返回 None。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CertEvent:
    all_domains: tuple[str, ...]
    issuer_o: str | None
    issuer_cn: str | None
    sha256: str
    not_before: int
    not_after: int
    seen: float
    source: str
    update_type: str


def _num(value: Any, kind: type[int] | type[float]) -> Any:
    try:
        return kind(value or 0)
    except (TypeError, ValueError):
        return kind(0)


def parse_message(raw: str | bytes) -> CertEvent | None:
    try:
        msg = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(msg, dict) or msg.get("message_type") != "certificate_update":
        return None
    data = msg.get("data")
    if not isinstance(data, dict):
        return None
    leaf = data.get("leaf_cert")
    if not isinstance(leaf, dict):
        return None
    domains = leaf.get("all_domains")
    if not isinstance(domains, list) or not domains:
        return None
    issuer_raw = leaf.get("issuer")
    issuer: dict[str, Any] = issuer_raw if isinstance(issuer_raw, dict) else {}
    source_raw = data.get("source")
    source: dict[str, Any] = source_raw if isinstance(source_raw, dict) else {}
    return CertEvent(
        all_domains=tuple(str(d) for d in domains),
        issuer_o=issuer.get("O"),
        issuer_cn=issuer.get("CN"),
        sha256=str(leaf.get("sha256") or leaf.get("fingerprint") or ""),
        not_before=_num(leaf.get("not_before"), int),
        not_after=_num(leaf.get("not_after"), int),
        seen=_num(data.get("seen"), float),
        source=str(source.get("name") or ""),
        update_type=str(data.get("update_type") or ""),
    )
