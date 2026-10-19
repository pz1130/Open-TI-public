"""文本关键词匹配（设计文档 7.1 / 7.2）：用于网页标题与正文、新闻、举报内容。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from opti.core.config import ProjectRules, Role, Term
from opti.core.normalize import compact_text, fold, normalize_text

_CJK = re.compile(r"[㐀-鿿豈-﫿]")
_CONTEXT_CHARS = 40


@dataclass(frozen=True)
class TextHit:
    set_name: str
    term: str
    mode: str
    role: str
    start: int
    end: int
    context: str


def _bounded(pattern_text: str, *, case_sensitive: bool) -> re.Pattern[str]:
    """两端加边界：ASCII 边缘只排除相邻的 ASCII 字母数字（允许 "Brand中文" 命中）。"""
    body = re.escape(pattern_text).replace(r"\ ", r"\s+")
    left = r"(?<![A-Za-z0-9])" if pattern_text[0].isascii() else r"(?<!\w)"
    right = r"(?![A-Za-z0-9])" if pattern_text[-1].isascii() else r"(?!\w)"
    return re.compile(left + body + right, 0 if case_sensitive else re.IGNORECASE)


@dataclass(frozen=True)
class _Compiled:
    set_name: str
    role: str
    term: Term
    pattern: re.Pattern[str] | None  # 非中文：在归一化视图上用正则匹配
    compact: str | None  # 中文：在紧凑视图上做子串匹配
    context_terms: tuple[str, ...]


class TextMatcher:
    def __init__(self, rules: ProjectRules) -> None:
        self._terms: list[_Compiled] = []
        roles: tuple[Role, ...] = ("match", "booster")
        for role in roles:
            for name, ts in rules.sets_with_role(role):
                self._terms.extend(self._compile(name, role, t) for t in ts.terms)
        self._negatives = [
            _bounded(normalize_text(t.value, casefold=False), case_sensitive=False)
            for _, ts in rules.sets_with_role("negative")
            for t in ts.terms
        ]

    @staticmethod
    def _compile(set_name: str, role: str, term: Term) -> _Compiled:
        ctx = term.require_any_within
        context_terms = tuple(fold(normalize_text(c)) for c in ctx.terms) if ctx else ()
        if _CJK.search(term.value):
            return _Compiled(set_name, role, term, None, compact_text(term.value), context_terms)
        value = normalize_text(term.value, casefold=False)
        pattern = _bounded(value, case_sensitive=term.case_sensitive)
        return _Compiled(set_name, role, term, pattern, None, context_terms)

    def match(self, text: str) -> list[TextHit]:
        view = normalize_text(text, casefold=False)
        if not view:
            return []
        folded = fold(view)
        compact = compact_text(text)
        negative_spans = [m.span() for p in self._negatives for m in p.finditer(view)]

        hits: list[TextHit] = []
        for c in self._terms:
            if c.compact is not None:
                i = compact.find(c.compact)
                if i >= 0:
                    context = compact[
                        max(0, i - _CONTEXT_CHARS) : i + len(c.compact) + _CONTEXT_CHARS
                    ]
                    hits.append(
                        TextHit(c.set_name, c.term.value, c.term.mode, c.role, -1, -1, context)
                    )
                continue
            assert c.pattern is not None
            for m in c.pattern.finditer(view):
                s, e = m.span()
                if any(ns <= s and e <= ne for ns, ne in negative_spans):
                    continue
                if c.context_terms and not self._has_context(folded, s, e, c):
                    continue
                context = view[max(0, s - _CONTEXT_CHARS) : e + _CONTEXT_CHARS]
                hits.append(TextHit(c.set_name, c.term.value, c.term.mode, c.role, s, e, context))
        return sorted(hits, key=lambda h: (h.start, h.term))

    def may_match(self, text: str) -> bool:
        """粗筛正文抓取候选；上下文和否定词留待完整匹配时检查。"""
        view = normalize_text(text, casefold=False)
        compact = compact_text(text)
        for candidate in self._terms:
            if candidate.role != "match":
                continue
            if candidate.compact is not None and candidate.compact in compact:
                return True
            if candidate.pattern is not None and candidate.pattern.search(view):
                return True
        return False

    @staticmethod
    def _has_context(folded: str, s: int, e: int, c: _Compiled) -> bool:
        assert c.term.require_any_within is not None
        w = c.term.require_any_within.window_chars
        window = folded[max(0, s - w) : e + w]
        return any(t in window for t in c.context_terms)
