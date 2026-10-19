"""Public GitHub code-hit identities and validation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from opti.core.scoring import CodeFacts
from opti.core.secret_guard import mask_deep, mask_text
from opti.core.secrets import is_critical_rule, is_sensitive_path, redact_text

REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
MAX_HITS = 50
CONTEXT_MAX_LINES = 7  # masked lines kept around one secret
CONTEXT_LINE_CHARS = 200
TERM_KINDS = frozenset({"domain", "internal"})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_SCAN_ERROR = re.compile(
    r"(?:clone_failed|clone_timeout|clone_head|clone_base|scan_timeout|"
    r"gitleaks:(?:report|-?\d+)|github:(?:\d+|network|invalid_json|invalid_base)|unavailable|invalid_repo|invalid_result)"
)


def repo_value(repo: str) -> str:
    return f"github.com/{repo.lower()}"


def disclosure_links(repo: str) -> dict[str, str]:
    return {
        "policy": f"https://github.com/{repo}/security/policy",
        "report": f"https://github.com/{repo}/security/advisories/new",
    }


def clean_repo_meta(raw: Any) -> dict[str, Any]:
    """Allowlist and clip public repository metadata (collector and platform both apply it)."""
    if not isinstance(raw, Mapping):
        return {}

    def text(key: str, limit: int) -> str:
        value = raw.get(key)
        return redact_text(" ".join(value.split()))[:limit] if isinstance(value, str) else ""

    def when(key: str) -> str:
        value = raw.get(key)
        return value if isinstance(value, str) and _ISO_TIME.fullmatch(value) else ""

    homepage = text("homepage", 200)
    owner_type = raw.get("owner_type")
    topics = raw.get("topics")
    return {
        "description": text("description", 300),
        "homepage": homepage if homepage.startswith("https://") else "",
        "owner": text("owner", 100),
        "owner_type": owner_type if owner_type in ("User", "Organization") else "",
        "fork": raw.get("fork") is True,
        "topics": [redact_text(t)[:50] for t in topics if isinstance(t, str) and t][:10]
        if isinstance(topics, list)
        else [],
        "created_at": when("created_at"),
        "pushed_at": when("pushed_at"),
    }


def parse_code_hit(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("code_hit must be a mapping")
    repo = str(raw.get("repo") or "")
    if not REPO_RE.fullmatch(repo) or ".." in repo:
        raise ValueError("invalid repository")
    repo = repo.lower()
    html_url = str(raw.get("html_url") or "")
    parsed = urlsplit(html_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
    ):
        raise ValueError("invalid GitHub file URL")
    if not parsed.path.lower().startswith(f"/{repo}/blob/"):
        raise ValueError("file URL does not belong to repository")
    kind = str(raw.get("term_kind") or "")
    if kind not in TERM_KINDS:
        raise ValueError("invalid term kind")
    fragments_raw = raw.get("fragments")
    fragments = (
        [redact_text(fragment)[:300] for fragment in fragments_raw if isinstance(fragment, str)][:3]
        if isinstance(fragments_raw, list)
        else []
    )
    return {
        "repo": repo,
        "path": str(raw.get("path") or "")[:500],
        "html_url": html_url[:1000],
        "blob_sha": str(raw.get("blob_sha") or "")[:64],
        "term": str(raw.get("term") or "")[:200],
        "term_kind": kind,
        "fork": bool(raw.get("fork")),
        "fragments": fragments,
    }


def merge_hits(previous: Sequence[Any], hit: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Keep the newest version of each matching path."""
    rest = [
        dict(old) for old in previous if isinstance(old, Mapping) and old.get("path") != hit["path"]
    ]
    return [dict(hit), *rest][:MAX_HITS]


def _age_days(value: Any, now: datetime) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    timestamp = (
        timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
    )
    return max((now - timestamp).days, 0)


def code_facts(
    hits: Sequence[Mapping[str, Any]], scan: Mapping[str, Any] | None, now: datetime
) -> CodeFacts:
    secrets = [
        secret for secret in (scan or {}).get("secrets") or [] if isinstance(secret, Mapping)
    ]
    hit_files = {str(hit.get("path")) for hit in hits}
    critical = sum(1 for secret in secrets if is_critical_rule(str(secret.get("rule") or "")))
    ages = [
        age for age in (_age_days(secret.get("date"), now) for secret in secrets) if age is not None
    ]
    return CodeFacts(
        hits=len(hits),
        sensitive_paths=sum(1 for hit in hits if is_sensitive_path(str(hit.get("path") or ""))),
        internal_terms=any(hit.get("term_kind") == "internal" for hit in hits),
        critical_secrets=critical,
        other_secrets=len(secrets) - critical,
        secret_in_hit_file=any(str(secret.get("file")) in hit_files for secret in secrets),
        newest_secret_age_days=min(ages) if ages else None,
    )


def _context(value: Any, exposed: Any) -> list[str]:
    """Masked context lines from a collector, masked again: a faulty node must not leak a key."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for line in value:
        if not isinstance(line, str):
            continue
        if isinstance(exposed, str) and exposed:
            line = line.replace(exposed, "[REDACTED]")
        out.append(mask_text(redact_text(line))[:CONTEXT_LINE_CHARS])
        if len(out) >= CONTEXT_MAX_LINES:
            break
    return out


def safe_scan(data: Mapping[str, Any], repo: str, now: datetime) -> dict[str, Any]:
    """Allowlist the remote scan result again before persisting it centrally."""
    secrets: list[dict[str, Any]] = []
    raw_secrets = data.get("secrets")
    if data.get("scanned") and isinstance(raw_secrets, list):
        for raw in raw_secrets[:200]:
            if not isinstance(raw, Mapping):
                continue
            # keyed HMAC from the collector; legacy bare "sha256" values are dropped, not stored
            digest = str(raw.get("fingerprint") or "").lower()
            if not _SHA256.fullmatch(digest):
                continue
            leaked = raw.get("Secret")

            def metadata(value: Any, limit: int, exposed: Any = leaked) -> str:
                text = str(value or "")[:limit]
                if isinstance(exposed, str) and exposed:
                    text = text.replace(exposed, "[REDACTED]")
                return redact_text(text)

            file = metadata(raw.get("file"), 300)
            commit = str(raw.get("commit") or "")
            commit = commit if _COMMIT.fullmatch(commit) else ""
            try:
                line = max(0, int(raw.get("line") or 0))
                length = max(0, int(raw.get("length") or 0))
            except (TypeError, ValueError):
                continue
            secrets.append(
                {
                    "rule": metadata(raw.get("rule") or "unknown", 100),
                    "description": metadata(raw.get("description"), 200),
                    "file": file,
                    "line": line,
                    "commit": commit,
                    "date": metadata(raw.get("date"), 50) or None,
                    "prefix": str(raw.get("prefix") or "")[:4],
                    "fingerprint": digest,
                    "length": length,
                    "url": f"https://github.com/{repo}/blob/{commit}/{quote(file)}#L{line}"
                    if commit
                    else "",
                    "context": _context(raw.get("context"), leaked),
                }
            )
    head = str(data.get("commit") or "")
    status = "ok" if data.get("scanned") else f"skipped:{str(data.get('skipped') or '')[:50]}"
    return {
        "scanned_at": now.isoformat(),
        "status": status,
        "commit": head if _COMMIT.fullmatch(head) else None,
        "total": len(secrets),
        "secrets": secrets,
        "repo_meta": mask_deep(clean_repo_meta(data.get("repo_meta"))),
    }


def sanitize_scan_result(data: Mapping[str, Any], value: str, now: datetime) -> dict[str, Any]:
    """Strip unexpected fields before a remote result is cached or returned."""
    repo = value.removeprefix("github.com/")
    if not REPO_RE.fullmatch(repo) or ".." in repo:
        return {"supported": False, "scanned": False, "error": "invalid_repo"}
    if data.get("scanned"):
        if not isinstance(data.get("secrets"), list) or not _COMMIT.fullmatch(
            str(data.get("commit") or "")
        ):
            return {"supported": True, "scanned": False, "error": "invalid_result"}
        safe = safe_scan(data, repo, now)
        if data.get("total") != safe["total"]:
            return {"supported": True, "scanned": False, "error": "invalid_result"}
        try:
            depth = max(0, min(int(data.get("depth") or 0), 1000))
        except (TypeError, ValueError):
            depth = 0
        return {
            "supported": True,
            "scanned": True,
            "commit": safe["commit"],
            "depth": depth,
            "total": safe["total"],
            "secrets": safe["secrets"],
            "repo_meta": safe["repo_meta"],
        }
    skipped = str(data.get("skipped") or "")
    if skipped in {"private", "too_large", "not_found"}:
        return {"supported": True, "scanned": False, "skipped": skipped}
    error = str(data.get("error") or "unavailable")
    return {
        "supported": True,
        "scanned": False,
        "error": error if _SCAN_ERROR.fullmatch(error) else "unavailable",
    }
