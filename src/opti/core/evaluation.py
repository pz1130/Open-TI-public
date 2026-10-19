"""Gold-set evaluation of ambiguous brand abbreviations in document text."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from opti.core.adjudication import AdjudicationError, Assessment, PublicInput, build_public_input
from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.core.text_match import TextMatcher
from opti.core.urls import UrlMatcher

FP_MAX = 0.10
RECALL_MIN = 0.90
EXPECTED = ("relevant", "irrelevant")


@dataclass(frozen=True)
class TextCase:
    text: str
    expected: str
    note: str


@dataclass(frozen=True)
class TextEvaluation:
    positives: int
    true_positives: int
    negatives: int
    false_positives: int
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.true_positives / self.positives if self.positives else 1.0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.negatives if self.negatives else 0.0

    @property
    def passed(self) -> bool:
        return self.fp_rate < FP_MAX and self.recall >= RECALL_MIN


def load_text_cases(path: Path) -> list[TextCase]:
    with path.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    cases = []
    for index, row in enumerate(rows, start=2):
        expected = (row.get("expected") or "").strip()
        if expected not in EXPECTED or not (row.get("text") or "").strip():
            raise ValueError(
                f"{path} 第 {index} 行不合法：expected 必须是 {'/'.join(EXPECTED)}，text 不能为空"
            )
        cases.append(TextCase(row["text"], expected, (row.get("note") or "").strip()))
    return cases


def evaluate_texts(rules: ProjectRules, cases: Sequence[TextCase]) -> TextEvaluation:
    matcher = TextMatcher(rules)
    true_positives = false_positives = 0
    failures: list[dict[str, Any]] = []
    for case in cases:
        terms = sorted({hit.term for hit in matcher.match(case.text) if hit.role == "match"})
        found = bool(terms)
        if case.expected == "relevant":
            true_positives += found
        else:
            false_positives += found
        if found != (case.expected == "relevant"):
            failures.append(
                {
                    "text": case.text[:120],
                    "expected": case.expected,
                    "terms": terms,
                    "note": case.note,
                }
            )
    positives = sum(case.expected == "relevant" for case in cases)
    return TextEvaluation(
        positives, true_positives, len(cases) - positives, false_positives, failures
    )


class _Assessor(Protocol):
    async def assess(self, inp: PublicInput) -> Assessment: ...


async def evaluate_texts_llm(
    rules: ProjectRules,
    cases: Sequence[TextCase],
    adjudicator: _Assessor,
    *,
    organization: str,
    short_name: str,
) -> tuple[TextEvaluation, TextEvaluation]:
    """比较规则与模型过滤后的文本分类效果。模型失败时保留规则结论。"""
    matcher = TextMatcher(rules)
    tp = fp = 0
    failures: list[dict[str, Any]] = []
    for case in cases:
        terms = sorted({hit.term for hit in matcher.match(case.text) if hit.role == "match"})
        verdict: str | None = None
        if terms:
            inp = build_public_input(
                {
                    "document": {"title": "", "source_name": "golden"},
                    "contexts": [case.text],
                    "terms": terms,
                },
                category="brand_mention",
                rules=rules,
                organization=organization,
                short_name=short_name,
            )
            with suppress(AdjudicationError):
                verdict = (await adjudicator.assess(inp)).verdict
        relevant = bool(terms) and verdict != "no"
        if case.expected == "relevant":
            tp += relevant
        else:
            fp += relevant
        if relevant != (case.expected == "relevant"):
            failures.append(
                {
                    "text": case.text[:120],
                    "expected": case.expected,
                    "terms": terms,
                    "llm": verdict,
                    "note": case.note,
                }
            )
    positives = sum(c.expected == "relevant" for c in cases)
    return evaluate_texts(rules, cases), TextEvaluation(
        positives, tp, len(cases) - positives, fp, failures
    )


SET_RECALL_MIN = 0.70  # 设计文档 1.4：召回率 MVP 目标


@dataclass(frozen=True)
class SetResult:
    name: str
    positives: int
    true_positives: int
    negatives: int
    false_positives: int
    recall_min: float
    fp_max: float  # 0 表示负样本一条都不能误报；否则误报率须小于该值
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.true_positives / self.positives if self.positives else 1.0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.negatives if self.negatives else 0.0

    @property
    def passed(self) -> bool:
        fp_ok = self.false_positives == 0 if self.fp_max == 0 else self.fp_rate < self.fp_max
        return self.recall >= self.recall_min and fp_ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "positives": self.positives, "true_positives": self.true_positives,
            "recall": round(self.recall, 3), "negatives": self.negatives, "false_positives": self.false_positives,
            "fp_rate": round(self.fp_rate, 3), "passed": self.passed, "failures": self.failures,
        }  # fmt: skip


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def evaluate_domains(rules: ProjectRules, path: Path) -> SetResult:
    """正样本 match；负样本（no_match / official / known_lookalike）一条都不能被判为 match。"""
    matcher = DomainMatcher(rules.domains)
    pos = tp = neg = fp = 0
    failures: list[dict[str, Any]] = []
    for row in _rows(path):
        m = matcher.match(row["domain"])
        actual = "no_match" if m is None else m.status
        hit = actual == "match"
        if row["expected"] == "match":
            pos, tp = pos + 1, tp + hit
        else:
            neg, fp = neg + 1, fp + hit
        if actual != row["expected"]:
            failures.append({"value": row["domain"], "expected": row["expected"], "actual": actual,
                             "note": row.get("note", "")})  # fmt: skip
    return SetResult("domains", pos, tp, neg, fp, SET_RECALL_MIN, 0.0, failures)


def evaluate_urls(rules: ProjectRules, path: Path) -> SetResult:
    """正样本 domain / url（判定种类也须一致才算通过，但召回只看是否命中）；负样本 none 不能命中。"""
    matcher = UrlMatcher(rules)
    pos = tp = neg = fp = 0
    failures: list[dict[str, Any]] = []
    for row in _rows(path):
        m = matcher.match(row["url"])
        actual = "none" if m is None or m.kind is None else m.kind
        hit = actual != "none"
        if row["expected"] in ("domain", "url"):
            pos, tp = pos + 1, tp + hit
        else:
            neg, fp = neg + 1, fp + hit
        if actual != row["expected"]:
            failures.append({"value": row["url"], "expected": row["expected"], "actual": actual,
                             "note": row.get("note", "")})  # fmt: skip
    return SetResult("urls", pos, tp, neg, fp, SET_RECALL_MIN, 0.0, failures)


def texts_result(ev: TextEvaluation) -> SetResult:
    failures = [
        {"value": f["text"], "expected": f["expected"], "note": f.get("note", "")}
        for f in ev.failures
    ]
    return SetResult("texts", ev.positives, ev.true_positives, ev.negatives, ev.false_positives, RECALL_MIN, FP_MAX,
                     failures)  # fmt: skip


def run_golden(rules: ProjectRules, root: Path) -> list[SetResult]:
    return [
        evaluate_domains(rules, root / "domains.csv"),
        evaluate_urls(rules, root / "urls.csv"),
        texts_result(evaluate_texts(rules, load_text_cases(root / "texts.csv"))),
    ]
