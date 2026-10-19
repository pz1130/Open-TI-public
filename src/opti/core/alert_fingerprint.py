"""忽略告警只比较可解释的关键事实，不比较抓取时间、HTML 或截图哈希。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _stable(value: Any) -> Any:
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, list):
        return sorted((_stable(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in sorted(value.items())}
    return value


def _url(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    query = sorted(
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_")
        and k.lower() not in {"fbclid", "gclid", "timestamp", "nonce", "session", "_"}
    )
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", urlencode(query), "")
    )


def fingerprint(
    category: str,
    severity: str,
    match: Mapping[str, Any],
    enrichment: Mapping[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {"category": category, "severity": severity}

    def pick(prefix: str, data: Any, keys: tuple[str, ...]) -> None:
        if not isinstance(data, dict) or data.get("error"):
            return
        for key in keys:
            if key in data:
                value = _url(data[key]) if key.endswith("url") else _stable(data[key])
                result[f"{prefix}.{key}"] = value

    for name, keys in {
        "dns": ("a", "aaaa", "cname", "mx", "nxdomain", "exists"),
        "tls": ("sha256", "not_after", "issuer_o", "issuer_cn", "subject_cn"),
        "rdap": ("registrar", "nameservers", "registrant"),
        "http_probe": (
            "status",
            "title",
            "final_url",
            "page_kind",
            "has_password_field",
            "brand_terms",
        ),
    }.items():
        wrapper = enrichment.get(name)
        data = wrapper.get("data") if isinstance(wrapper, dict) else None
        if (
            name == "http_probe"
            and isinstance(data, dict)
            and isinstance(data.get("status"), int)
            and data["status"] >= 500
        ):
            continue
        pick(name, data, keys)
    pick("match", dict(match), ("signal", "issuer_o", "platform", "url", "kind"))
    pick("certificate", match.get("certificate"), ("sha256", "not_after", "issuer_o"))
    pick(
        "social", match.get("social"), ("handle", "display_name", "bio", "avatar_sha256", "gone_at")
    )
    pick("document", match.get("document"), ("title", "url"))
    pick("indicator", match.get("indicator"), ("type", "value"))
    pick(
        "exposure",
        match.get("exposure"),
        ("data_classes", "affected", "verified", "fabricated", "stealer_log"),
    )
    pick("kev", match.get("kev"), ("cve_id", "vendor", "product", "ransomware", "required_action"))
    pick("post", match.get("post"), ("group", "victim", "domain", "description", "links"))
    hits = match.get("hits")
    if isinstance(hits, list):
        result["code.hits"] = _stable(
            [
                {k: row[k] for k in ("path", "blob_sha", "term") if k in row}
                for row in hits
                if isinstance(row, dict)
            ]
        )
    # 代码泄漏比较安全指纹和文件位置，不复制密钥值或扫描时间。
    scan = match.get("scan")
    if isinstance(scan, dict):
        secrets = scan.get("secrets")
        if isinstance(secrets, list):
            result["code.secrets"] = _stable(
                [
                    {k: row[k] for k in ("sha256", "file", "rule") if k in row}
                    for row in secrets
                    if isinstance(row, dict)
                ]
            )
    return result


def changed(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    # 缺失或失败的富化结果不算事实变化；成功取得的新事实参与比较。
    return any(key not in previous or previous[key] != value for key, value in current.items())
