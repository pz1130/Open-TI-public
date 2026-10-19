"""Redact possible credentials before code-search snippets or scan findings leave a collector."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

REDACTED = "…[REDACTED]"  # 无密钥形式：仅用于日志兜底与私钥块
REDACTED_MARK = "…[REDACTED"
MASK_KEY_ENV = "OPTI_SECRET_MASK_KEY"
MIN_MASK_KEY_LEN = 32
MAX_SECRETS = 200
CRITICAL_RULE_PREFIXES = (
    "aws-", "gcp-", "azure-", "alibaba-", "private-key", "github-", "gitlab-", "bitbucket-",
    "slack-", "stripe-", "twilio-", "sendgrid-", "mailgun-", "heroku-", "digitalocean-",
    "openai-", "anthropic-", "hashicorp-", "npm-access-token", "pypi-upload-token", "jwt",
)  # fmt: skip
_SENSITIVE_PATH = re.compile(
    r"(^|/)(\.env(\..*)?|[^/]+\.env|id_(rsa|dsa|ecdsa|ed25519)|credentials?(\..*)?|secrets?(\..*)?|web\.config|"
    r"settings\.py|wp-config\.php|docker-compose[^/]*|[^/]+\.(pem|key|p12|pfx|jks|kdbx|ovpn|ini|cfg|conf|"
    r"properties|ya?ml|tfvars|tfstate))$",
    re.IGNORECASE,
)
_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b"),
    re.compile(r"(?<![\w/.:-])[A-Za-z0-9+/_=-]{32,}(?![\w/.:-])"),
)
_ASSIGN = re.compile(
    r"(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w.-]*)"
    r"(\s*[:=]\s*)([\"']?)([^\s\"']{4,})"
)
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")


class MaskKeyMissing(RuntimeError):
    """OPTI_SECRET_MASK_KEY 未设置或过短：拒绝生成遮蔽值（fail closed）。"""


def mask_key() -> bytes:
    """Platform-wide HMAC key; collector and platform must use the same value."""
    key = os.environ.get(MASK_KEY_ENV, "")
    if len(key) < MIN_MASK_KEY_LEN:
        raise MaskKeyMissing(
            f"{MASK_KEY_ENV} 未设置或少于 {MIN_MASK_KEY_LEN} 个字符（平台与采集节点须一致）"
        )
    return key.encode()


def require_mask_key() -> None:
    mask_key()


def fingerprint(value: str) -> str:
    """Keyed HMAC-SHA256 of a secret; never a bare hash (outsiders cannot test guesses)."""
    return hmac.new(mask_key(), value.encode(), hashlib.sha256).hexdigest()


def mask(value: str) -> str:
    """'AKIA…[REDACTED:1a2b3c4d]': distinct secrets with the same prefix stay distinct."""
    return (value[:4] if len(value) >= 8 else "") + f"{REDACTED_MARK}:{fingerprint(value)[:8]}]"


def redact_text(text: str) -> str:
    """Conservatively mask common credential shapes in search snippets."""
    out = _PATTERNS[0].sub("-----BEGIN PRIVATE KEY-----" + REDACTED, text)
    out = _ASSIGN.sub(
        lambda m: (
            m.group(0)
            if REDACTED_MARK in m.group(4)
            else f"{m.group(1)}{m.group(2)}{m.group(3)}{mask(m.group(4))}"
        ),
        out,
    )
    for pattern in _PATTERNS[1:]:
        out = pattern.sub(
            lambda m: m.group(0) if REDACTED_MARK in m.group(0) else mask(m.group(0)), out
        )
    return out


def is_critical_rule(rule_id: str) -> bool:
    return rule_id.lower().startswith(CRITICAL_RULE_PREFIXES)


def is_sensitive_path(path: str) -> bool:
    return bool(_SENSITIVE_PATH.search(path))


def redact_findings(
    raw: Iterable[Any], repo: str, *, limit: int = MAX_SECRETS
) -> list[dict[str, Any]]:
    """Allowlist gitleaks fields; never return Secret, Match, author or commit message."""
    from opti.core.secret_guard import register_discovered  # local: avoids import cycle

    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for finding in raw:
        if not isinstance(finding, dict):
            continue
        secret = finding.get("Secret")
        if not isinstance(secret, str) or not secret:
            continue
        digest = fingerprint(secret)  # keyed HMAC, never a bare SHA-256 of the secret
        register_discovered(secret)  # digest only: lets outbound clients refuse this value

        def metadata(value: Any, limit: int, found: str = secret) -> str:
            return redact_text(str(value or "")[:limit].replace(found, mask(found)))

        file = metadata(finding.get("File"), 300)
        if (digest, file) in seen:
            continue
        seen.add((digest, file))
        raw_commit = str(finding.get("Commit") or "")
        commit = raw_commit if _COMMIT.fullmatch(raw_commit) else ""
        try:
            line = max(0, int(finding.get("StartLine") or 0))
        except (TypeError, ValueError):
            line = 0
        out.append(
            {
                "rule": metadata(finding.get("RuleID") or "unknown", 100),
                "description": metadata(finding.get("Description"), 200),
                "file": file,
                "line": line,
                "commit": commit,
                "date": metadata(finding.get("Date"), 50) or None,
                "prefix": secret[:4] if len(secret) >= 8 else "",
                "fingerprint": digest,
                "length": len(secret),
                "url": f"https://github.com/{repo}/blob/{commit}/{quote(file)}#L{line}"
                if commit
                else "",
            }
        )
        if len(out) >= limit:
            break
    return out
