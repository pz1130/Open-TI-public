"""Fetch public HTML safely and extract article text on the collector."""

from __future__ import annotations

import asyncio

from opti.core.extract import Article, extract_article
from opti.sdk.safefetch import FetchError, SafeFetcher, ascii_url


async def fetch_article(fetcher: SafeFetcher, url: str) -> Article | None:
    target = ascii_url(url)
    if target is None:
        return None
    try:
        response, final_url, _ = await fetcher.open(target)
    except FetchError:
        return None
    if (
        response.status_code >= 400
        or "html" not in response.headers.get("content-type", "").lower()
    ):
        return None
    return await asyncio.to_thread(extract_article, response.text, final_url)
