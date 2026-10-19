"""Hard guard for discovered credentials (design doc v0.2, 2.3: never verify, never use).

Two layers, both independent of any single call site:

* ``mask_text`` / ``mask_deep`` replace high-confidence credential shapes with
  ``prefix…[REDACTED:<8 hex of HMAC>]`` before anything is persisted, logged, exported
  (STIX), sent to an LLM or pushed to SIEM / ticket / webhook endpoints.
* ``assert_no_secret`` is called by every outbound HTTP client. It refuses a
  request whose URL, query, body - or headers - carry a value the secret scanner
  discovered in this process (tracked only by SHA-256), and refuses URL, query
  or body carrying a high-confidence credential shape. Headers are not
  pattern-checked because they legitimately carry the platform's own configured
  API tokens; a configured token that equals a discovered secret is still refused.

The raw value of a discovered secret is never stored here: only its digest and length.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any

from opti.core.secrets import REDACTED, MaskKeyMissing, mask

# Shapes that are credentials with near certainty; deliberately excludes the generic
# "long random string" rule so hashes, ids and fingerprints are left alone.
HIGH_CONFIDENCE = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
)
_TOKEN = re.compile(r"[^\s\"'<>(){}\[\],;`]{8,}")


class SecretEgressBlocked(RuntimeError):
    """An outbound request would have carried a discovered secret / credential."""

    def __init__(self, where: str, reason: str) -> None:
        super().__init__(f"blocked outbound {where}: {reason}")
        self.where, self.reason = where, reason


class _Registry:
    """SHA-256 digests (by length) of secrets the scanner discovered in this process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_len: dict[int, set[str]] = {}

    def add_digest(self, digest: str, length: int) -> None:
        if length >= 8 and re.fullmatch(r"[0-9a-f]{64}", digest):
            with self._lock:
                self._by_len.setdefault(length, set()).add(digest)

    def clear(self) -> None:
        with self._lock:
            self._by_len.clear()

    def hit(self, text: str) -> bool:
        if not self._by_len:
            return False
        lengths = self._by_len
        for m in _TOKEN.finditer(text):
            tok = m.group(0)
            if len(tok) > 512:  # long blobs: exact-token check only
                if hashlib.sha256(tok.encode()).hexdigest() in lengths.get(len(tok), ()):
                    return True
                continue
            # the secret may sit inside a longer token (e.g. key=VALUE, Bearer VALUE)
            for n, digests in lengths.items():
                if n > len(tok):
                    continue
                for i in range(len(tok) - n + 1):
                    if hashlib.sha256(tok[i : i + n].encode()).hexdigest() in digests:
                        return True
        return False


discovered = _Registry()


def register_discovered(secret: str) -> None:
    discovered.add_digest(hashlib.sha256(secret.encode()).hexdigest(), len(secret))


def mask_text(text: str, *, keyed: bool = True) -> str:
    """Mask credential shapes as ``prefix…[REDACTED:hmac8]``.

    ``keyed=False`` (log filter only) drops the tag instead of needing the key.
    """
    out = HIGH_CONFIDENCE[0].sub("-----BEGIN PRIVATE KEY-----" + REDACTED, text)
    tag = mask if keyed else (lambda v: (v[:4] if len(v) >= 8 else "") + REDACTED)
    for pattern in HIGH_CONFIDENCE[1:]:
        out = pattern.sub(lambda m: tag(m.group(0)), out)
    return out


def mask_deep(value: Any) -> Any:
    """Recursively mask strings in JSON-like data (dict keys are left alone)."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, Mapping):
        return {k: mask_deep(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_deep(v) for v in value]
    return value


def mask_item(item: Any) -> Any:
    """Mask pastes, documents and any other ingested text of a RawItem before it is persisted."""
    from dataclasses import replace

    url = mask_text(item.url) if isinstance(item.url, str) else item.url
    return replace(
        item,
        source_item_id=mask_text(item.source_item_id),
        url=url,
        payload=mask_deep(item.payload),
    )


def _flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(f"{k}={_flatten(v)}" for k, v in value.items())
    if isinstance(value, Iterable):
        return "\n".join(_flatten(v) for v in value)
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def find_secret(text: str) -> str | None:
    for pattern in HIGH_CONFIDENCE:
        if pattern.search(text):
            return "credential pattern"
    return None


def assert_no_secret(
    where: str, *, url: Any = None, params: Any = None, body: Any = None, headers: Any = None
) -> None:
    visible = "\n".join(_flatten(x) for x in (url, params, body))
    reason = find_secret(visible)
    if reason:
        raise SecretEgressBlocked(where, reason)
    if discovered.hit(visible + "\n" + _flatten(headers)):
        raise SecretEgressBlocked(where, "discovered secret")


class MaskSecretsFilter(logging.Filter):
    """Mask credential shapes in log messages (installed on root handlers by the CLI)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        try:
            masked = mask_text(msg)
        except MaskKeyMissing:  # logging must never fail open nor crash
            masked = mask_text(msg, keyed=False)
        if masked != msg:
            record.msg, record.args = masked, None
        return True


def install_log_filter(logger: logging.Logger | None = None) -> None:
    root = logger or logging.getLogger()
    for handler in root.handlers:
        if not any(isinstance(f, MaskSecretsFilter) for f in handler.filters):
            handler.addFilter(MaskSecretsFilter())
