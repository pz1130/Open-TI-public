"""Document payloads, fingerprints, near-duplicate hashes and search excerpts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from opti.core.normalize import normalize_text
from opti.core.text_match import TextHit
from opti.core.urls import normalize_url

MAX_TEXT = 200_000
MAX_TITLE = 500
MAX_SUMMARY = 2_000
MAX_CONTEXTS = 10
CONTEXT_CHARS = 300
MAX_SEARCH_TEXT = 20_000
NEAR_DUP_BITS = 10
DOC_KINDS = frozenset({"intel"})
_TOKEN = re.compile(r"[a-z0-9]+|[㐀-鿿豈-﫿]")


class DocumentError(ValueError):
    pass


@dataclass(frozen=True)
class DocInput:
    url: str | None
    url_normalized: str | None
    title: str
    summary: str
    text: str
    language: str | None
    published_at: datetime | None
    source_name: str
    query: str | None
    kind: str | None = None


def _clean(value: Any, limit: int) -> str:
    return " ".join(value.split())[:limit] if isinstance(value, str) else ""


def document_payload(
    *,
    url: str | None,
    title: str,
    summary: str = "",
    text: str = "",
    language: str | None = None,
    published_at: datetime | None = None,
    source_name: str = "",
    query: str | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    doc = {
        "url": url,
        "title": title,
        "summary": summary,
        "text": text[:MAX_TEXT],
        "language": language,
        "published_at": published_at.isoformat() if published_at else None,
        "source_name": source_name,
        "query": query,
    }
    if kind:
        doc["kind"] = kind
    return {"document": doc}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)


def parse_document(payload: Mapping[str, Any]) -> DocInput:
    raw = payload.get("document")
    if not isinstance(raw, Mapping):
        raise DocumentError("缺少 document")
    url = raw.get("url") or None
    if url is not None and not isinstance(url, str):
        raise DocumentError("url 只能是 http(s)")
    normalized = normalize_url(url) if url else None
    if url is not None and normalized is None:
        raise DocumentError("url 只能是合法的 http(s) 地址")
    title = _clean(raw.get("title"), MAX_TITLE)
    if url is None and not title:
        raise DocumentError("url 与 title 至少要有一个")
    return DocInput(
        url=url[:2_000] if url else None,
        url_normalized=normalized,
        title=title,
        summary=_clean(raw.get("summary"), MAX_SUMMARY),
        text=str(raw.get("text") or "")[:MAX_TEXT],
        language=_clean(raw.get("language"), 10).lower() or None,
        published_at=_time(raw.get("published_at")),
        source_name=_clean(raw.get("source_name"), 200),
        query=_clean(raw.get("query"), 500) or None,
        kind=raw.get("kind")
        if isinstance(raw.get("kind"), str) and raw.get("kind") in DOC_KINDS
        else None,
    )


def fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode()).hexdigest()


def _features(text: str) -> set[str]:
    tokens = _TOKEN.findall(normalize_text(text))
    if len(tokens) < 3:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i : i + 3]) for i in range(len(tokens) - 2)}


def simhash64(text: str) -> int:
    weights = [0] * 64
    for feature in _features(text):
        value = int.from_bytes(hashlib.blake2b(feature.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if (value >> bit) & 1 else -1
    return sum(1 << bit for bit in range(64) if weights[bit] > 0)


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def to_signed64(value: int) -> int:
    return value - (1 << 64) if value >= 1 << 63 else value


def from_signed64(value: int) -> int:
    return value + (1 << 64) if value < 0 else value


def select_contexts(hits: Iterable[TextHit]) -> list[str]:
    contexts: dict[str, None] = {}
    for hit in hits:
        context = " ".join(hit.context.split())[:CONTEXT_CHARS]
        if context:
            contexts.setdefault(context, None)
        if len(contexts) >= MAX_CONTEXTS:
            break
    return list(contexts)


def build_search_text(title: str, summary: str, contexts: Iterable[str]) -> str:
    return normalize_text(" ".join([title, summary, *contexts]))[:MAX_SEARCH_TEXT]
