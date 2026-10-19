"""Extract article text for matching without persisting page bodies."""

from __future__ import annotations

import re
from dataclasses import dataclass

import trafilatura

MAX_ARTICLE_CHARS = 200_000
MIN_ARTICLE_CHARS = 80
MAX_HTML_CHARS = 2_000_000
_LANG = re.compile(r"<html\b[^>]*\blang\s*=\s*[\"']?([A-Za-z]{2,3})", re.IGNORECASE)


@dataclass(frozen=True)
class Article:
    url: str
    title: str
    text: str
    language: str | None


def extract_article(html: str, url: str) -> Article | None:
    html = html[:MAX_HTML_CHARS]
    text = trafilatura.extract(
        html,
        url=url,
        include_comments=False,
        include_tables=False,
        favor_precision=True,
        output_format="txt",
    )
    if not text or len(text.strip()) < MIN_ARTICLE_CHARS:
        return None
    metadata = trafilatura.extract_metadata(html)
    title = (metadata.title or "") if metadata is not None else ""
    match = _LANG.search(html)
    return Article(
        url=url,
        title=" ".join(title.split())[:500],
        text=text.strip()[:MAX_ARTICLE_CHARS],
        language=match.group(1).lower() if match else None,
    )
