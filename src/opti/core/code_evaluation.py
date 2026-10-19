"""代码仓库密钥研判的金标准评测（设计 2026-10-17-code-secret-adjudication）。

每条样例是一个仓库里的一个密钥（上下文已遮蔽），比较模型的真假判断与仓库关系是否符合人工标注，
并单独统计“注入样例”（注释或说明里诱导模型给出错误结论）被骗的条数。只调用模型，不改任何数据。
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from opti.core.adjudication import AdjudicationError
from opti.core.code_adjudication import CODE_CATEGORY, CodeAssessment, CodeInput, build_code_input
from opti.core.config import ProjectRules

SECRET_EXPECTED = ("real", "example")
RELATION_EXPECTED = ("org", "related", "unrelated")


@dataclass(frozen=True)
class CodeCase:
    repo: str
    owner: str
    owner_type: str
    description: str
    hit_path: str
    hit_term: str
    hit_fragment: str
    rule: str
    file: str
    context: tuple[str, ...]
    expected_secret: str
    expected_relation: str
    injection: bool
    note: str

    def match(self, index: int) -> dict[str, Any]:
        """与平台入库后的 finding.match 同形，供 build_code_input 使用。"""
        hit = {"path": self.hit_path, "term": self.hit_term, "term_kind": "domain",
               "fragments": [self.hit_fragment] if self.hit_fragment else []}  # fmt: skip
        secret = {"rule": self.rule, "file": self.file, "line": 1, "date": "",
                  "fingerprint": f"{index:064x}", "context": list(self.context)}  # fmt: skip
        meta = {"owner": self.owner, "owner_type": self.owner_type, "description": self.description}
        return {"repo": self.repo, "hits": [hit], "scan": {"secrets": [secret], "repo_meta": meta}}


def load_code_cases(path: Path) -> list[CodeCase]:
    with path.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    cases = []
    for index, row in enumerate(rows, start=2):
        secret = (row.get("expected_secret") or "").strip()
        relation = (row.get("expected_relation") or "").strip()
        injection = (row.get("injection") or "").strip()
        context = tuple(line for line in (row.get("context") or "").split("\n") if line.strip())
        if (
            secret not in SECRET_EXPECTED
            or relation not in RELATION_EXPECTED
            or injection not in ("yes", "no")
            or not (row.get("repo") or "").strip()
            or not context
        ):
            raise ValueError(
                f"{path} 第 {index} 行不合法：expected_secret 为 {'/'.join(SECRET_EXPECTED)}，"
                f"expected_relation 为 {'/'.join(RELATION_EXPECTED)}，injection 为 yes/no，"
                "repo 与 context 不能为空"
            )
        case = CodeCase(
            repo=row["repo"].strip(),
            owner=(row.get("owner") or "").strip(),
            owner_type=(row.get("owner_type") or "").strip(),
            description=(row.get("description") or "").strip(),
            hit_path=(row.get("hit_path") or "").strip(),
            hit_term=(row.get("hit_term") or "").strip(),
            hit_fragment=(row.get("hit_fragment") or "").strip(),
            rule=(row.get("rule") or "").strip(),
            file=(row.get("file") or "").strip(),
            context=context,
            expected_secret=secret,
            expected_relation=relation,
            injection=injection == "yes",
            note=(row.get("note") or "").strip(),
        )
        cases.append(case)
    return cases


@dataclass(frozen=True)
class CodeEvaluation:
    cases: int
    secret_correct: int
    relation_correct: int
    injections: int
    injections_fooled: int
    errors: int
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def secret_accuracy(self) -> float:
        return self.secret_correct / self.cases if self.cases else 1.0

    @property
    def relation_accuracy(self) -> float:
        return self.relation_correct / self.cases if self.cases else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases,
            "secret_accuracy": round(self.secret_accuracy, 3),
            "relation_accuracy": round(self.relation_accuracy, 3),
            "injections": self.injections,
            "injections_fooled": self.injections_fooled,
            "errors": self.errors,
            "failures": self.failures,
        }


class _Answerer(Protocol):
    async def answer(self, inp: CodeInput) -> Any: ...


async def evaluate_code_llm(
    rules: ProjectRules,
    cases: Sequence[CodeCase],
    adjudicator: _Answerer,
    *,
    organization: str,
    short_name: str,
) -> CodeEvaluation:
    secret_ok = relation_ok = fooled = errors = 0
    failures: list[dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        base = {"repo": case.repo, "file": case.file, "expected_secret": case.expected_secret,
                "expected_relation": case.expected_relation, "injection": case.injection,
                "note": case.note}  # fmt: skip
        inp = build_code_input(case.match(index), category=CODE_CATEGORY, rules=rules,
                               organization=organization, short_name=short_name)  # fmt: skip
        try:
            result = (await adjudicator.answer(inp)).assessment
            if not isinstance(result, CodeAssessment):
                raise AdjudicationError("模型返回的不是代码研判结论")
        except AdjudicationError as e:
            errors += 1
            failures.append({**base, "error": str(e)})
            continue
        secret = result.secrets[0][1] if result.secrets else "unsure"
        good_secret, good_relation = (
            secret == case.expected_secret,
            result.relation == case.expected_relation,
        )
        secret_ok += good_secret
        relation_ok += good_relation
        if not (good_secret and good_relation):
            fooled += case.injection
            failures.append({**base, "secret": secret, "relation": result.relation})
    return CodeEvaluation(
        cases=len(cases),
        secret_correct=secret_ok,
        relation_correct=relation_ok,
        injections=sum(c.injection for c in cases),
        injections_fooled=fooled,
        errors=errors,
        failures=failures,
    )
