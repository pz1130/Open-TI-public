import json
from pathlib import Path

import pytest

from opti.cli import main
from opti.core.adjudication import Assessment, PublicInput
from opti.core.config import ProjectRules
from opti.core.evaluation import (
    FP_MAX,
    RECALL_MIN,
    evaluate_texts,
    evaluate_texts_llm,
    load_text_cases,
)

GOLDEN = Path(__file__).resolve().parents[1] / "eval" / "golden" / "texts.csv"


def test_golden_file_has_both_classes() -> None:
    cases = load_text_cases(GOLDEN)
    assert sum(case.expected == "relevant" for case in cases) >= 10
    assert sum(case.expected == "irrelevant" for case in cases) >= 20


def test_golden_texts(sbr_rules: ProjectRules) -> None:
    result = evaluate_texts(sbr_rules, load_text_cases(GOLDEN))
    assert result.fp_rate < FP_MAX, result.failures
    assert result.recall >= RECALL_MIN, result.failures


def test_eval_cli(sbr_rules_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--rules", str(sbr_rules_path), "eval-texts", "--file", str(GOLDEN)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["passed"] is True
    assert summary["negatives"] == 20 and summary["false_positives"] == 1
    bad = tmp_path / "bad.csv"
    bad.write_text(
        'text,expected,note\n"SBR Cluster rocks, Springfield and ORBIT too",irrelevant,x\n'
        '"Nothing here",relevant,y\n',
        encoding="utf-8",
    )
    assert main(["--rules", str(sbr_rules_path), "eval-texts", "--file", str(bad)]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["passed"] is False and summary["failures"]


class _FakeAdjudicator:
    backend = "fake"
    model = "fake"

    async def assess(self, inp: PublicInput) -> Assessment:
        verdict = "no" if any("Shared Backup Repository" in c for c in inp.contexts) else "yes"
        return Assessment(verdict, None, 0.9, "", "")


async def test_llm_comparison(sbr_rules: ProjectRules) -> None:
    cases = load_text_cases(GOLDEN)
    rules_only, with_llm = await evaluate_texts_llm(
        sbr_rules, cases, _FakeAdjudicator(), organization="Sample Brand", short_name="SBR"
    )
    assert rules_only.false_positives == 1 and with_llm.false_positives == 0
    assert with_llm.true_positives == rules_only.true_positives == 12
    assert with_llm.failures == []
