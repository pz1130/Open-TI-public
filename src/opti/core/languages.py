"""Offline language detection for matched documents without source language metadata."""

from __future__ import annotations

import re
from functools import lru_cache

from lingua import LanguageDetector, LanguageDetectorBuilder

MAX_SAMPLE_CHARS = 2_000
MIN_LETTERS = 24
_URL = re.compile(r"https?://\S+", re.I)


@lru_cache(maxsize=1)
def _detector() -> LanguageDetector:
    # A single, lazily loaded detector is shared across worker tasks. No API call is made.
    return (
        LanguageDetectorBuilder.from_all_spoken_languages()
        .with_minimum_relative_distance(0.1)
        .build()
    )


def detect_language(text: str) -> str | None:
    """Return a lower-case ISO 639-1 code, or unknown for short/ambiguous text."""
    sample = _URL.sub(" ", text[:MAX_SAMPLE_CHARS]).strip()
    if sum(char.isalpha() for char in sample) < MIN_LETTERS:
        return None
    language = _detector().detect_language_of(sample)
    return language.iso_code_639_1.name.lower() if language is not None else None
