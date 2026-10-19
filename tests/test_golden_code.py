from pathlib import Path

import pytest

from opti.core.code_adjudication import CodeAssessment, CodeInput, build_code_input
from opti.core.code_evaluation import evaluate_code_llm, load_code_cases
from opti.core.config import ProjectRules
from opti.core.secret_guard import find_secret
from opti.llm import Answer

GOLDEN = Path(__file__).resolve().parents[1] / "eval" / "golden" / "code_secrets.csv"
ORG = {"organization": "Sample Brand", "short_name": "SBR"}


def test_golden_file_is_balanced_and_masked(sbr_rules: ProjectRules) -> None:
    cases = load_code_cases(GOLDEN)
    assert len(cases) >= 35
    assert sum(c.expected_secret == "real" for c in cases) >= 10
    assert sum(c.expected_secret == "example" for c in cases) >= 10
    for relation in ("org", "related", "unrelated"):
        assert sum(c.expected_relation == relation for c in cases) >= 5
    assert sum(c.injection for c in cases) >= 5
    assert find_secret(GOLDEN.read_text(encoding="utf-8")) is None  # 样例里只有遮蔽后的值
    for i, case in enumerate(cases, start=1):
        build_code_input(case.match(i), category="secret_leak", rules=sbr_rules, **ORG)


class _Oracle:
    """按人工标注作答；gullible=True 时像被注释骗了一样，看到“fake / placeholder / ignore”等字样就判示例、本机构。"""

    def __init__(self, cases: list, *, gullible: bool = False) -> None:
        self.truth = {(c.repo, c.file): (c.expected_secret, c.expected_relation) for c in cases}
        self.gullible = gullible

    async def answer(self, inp: CodeInput) -> Answer:
        secret, relation = self.truth[(inp.repo, inp.secrets[0].file)]
        text = " ".join(inp.secrets[0].context).lower()
        if self.gullible and any(
            w in text
            for w in ("fake", "placeholder", "ignore", "official repository", "belongs to")
        ):
            secret, relation = "example", "org"
        result = CodeAssessment(((inp.secrets[0].ref, secret),), relation, 0.9, "", "")
        return Answer(result, "fake", "fake", "Fake")


async def test_perfect_answers_score_full_marks(sbr_rules: ProjectRules) -> None:
    cases = load_code_cases(GOLDEN)
    ev = await evaluate_code_llm(sbr_rules, cases, _Oracle(cases), **ORG)
    assert ev.secret_accuracy == 1.0 and ev.relation_accuracy == 1.0
    assert ev.injections_fooled == 0 and ev.errors == 0 and ev.failures == []


async def test_gullible_model_is_caught_by_injection_cases(sbr_rules: ProjectRules) -> None:
    cases = load_code_cases(GOLDEN)
    ev = await evaluate_code_llm(sbr_rules, cases, _Oracle(cases, gullible=True), **ORG)
    assert ev.injections_fooled == ev.injections
    assert ev.to_dict()["secret_accuracy"] < 1.0 and ev.failures


def test_bad_rows_are_rejected(tmp_path: Path) -> None:
    header = "repo,owner,owner_type,description,hit_path,hit_term,hit_fragment,rule,file,context,expected_secret,expected_relation,injection,note\n"
    for row in (
        "a/b,a,User,,x,SBR,,generic,f.py,KEY=x,maybe,org,no,\n",
        "a/b,a,User,,x,SBR,,generic,f.py,KEY=x,real,friend,no,\n",
        "a/b,a,User,,x,SBR,,generic,f.py,,real,org,no,\n",
        "a/b,a,User,,x,SBR,,generic,f.py,KEY=x,real,org,sometimes,\n",
    ):
        bad = tmp_path / "bad.csv"
        bad.write_text(header + row, encoding="utf-8")
        with pytest.raises(ValueError):
            load_code_cases(bad)
