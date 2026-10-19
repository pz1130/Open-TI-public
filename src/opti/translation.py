"""Bounded translation through a self-hosted service on a local Unix socket."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Protocol

import httpx

MAX_TEXTS = 11
MAX_CHARS = 4_000
MAX_RESPONSE_BYTES = 32_000
_CODE = re.compile(r"[a-z]{2}\Z")


class TranslationError(Exception):
    pass


class Translator(Protocol):
    async def translate(self, texts: list[str], *, source: str, target: str) -> list[str]: ...


class LocalTranslator:
    def __init__(self, socket: Path, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not socket.is_absolute():
            raise ValueError("translation socket must be an absolute path")
        self._client = httpx.AsyncClient(
            transport=transport or httpx.AsyncHTTPTransport(uds=str(socket)),
            base_url="http://local-translation",
            timeout=httpx.Timeout(15, connect=2),
            follow_redirects=False,
            trust_env=False,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def translate(self, texts: list[str], *, source: str, target: str) -> list[str]:
        if (
            not _CODE.fullmatch(source)
            or not _CODE.fullmatch(target)
            or source == target
            or not 1 <= len(texts) <= MAX_TEXTS
            or any(not value or len(value) > MAX_CHARS for value in texts)
            or sum(map(len, texts)) > MAX_CHARS
        ):
            raise ValueError("invalid translation request")
        try:
            async with self._client.stream(
                "POST",
                "/translate",
                json={"q": texts, "source": source, "target": target, "format": "text"},
            ) as response:
                if response.status_code != 200:
                    raise TranslationError("local translation service rejected request")
                if "application/json" not in response.headers.get("content-type", ""):
                    raise TranslationError("local translation service returned invalid content")
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise TranslationError("local translation response is too large")
        except httpx.HTTPError as exc:
            raise TranslationError("local translation service is unavailable") from exc
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TranslationError("local translation service returned invalid JSON") from exc
        values = data.get("translatedText") if isinstance(data, dict) else None
        if (
            not isinstance(values, list)
            or len(values) != len(texts)
            or any(not isinstance(value, str) or len(value) > MAX_CHARS for value in values)
        ):
            raise TranslationError("local translation service returned invalid text")
        return values
