"""文本归一化（设计文档 7.4）：只用于生成匹配副本，原文保留用于证据。"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from opencc import OpenCC

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎"), None)
_WHITESPACE = re.compile(r"\s+")
# 紧凑视图去掉的分隔符：空白、标点、符号、下划线（诈骗文本常写成"样·本·品·牌"规避检测）
_SEPARATORS = re.compile(r"[\W_]+")


@lru_cache(maxsize=1)
def _t2s() -> OpenCC:
    return OpenCC("t2s")


def to_simplified(text: str) -> str:
    return str(_t2s().convert(text))


def fold(text: str) -> str:
    """逐字符转小写；转换后长度会变化的字符（如 İ）保持原样，保证位置对齐。"""
    return "".join(lc if len(lc := c.lower()) == 1 else c for c in text)


def normalize_text(text: str, *, casefold: bool = True) -> str:
    s = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    s = to_simplified(s)
    if casefold:
        s = s.casefold()
    return _WHITESPACE.sub(" ", s).strip()


def compact_text(text: str) -> str:
    return _SEPARATORS.sub("", normalize_text(text))
