import json
import shutil
from pathlib import Path

import pytest

from opti.cli import main
from opti.core.config import ProjectRules
from opti.core.evaluation import SetResult, run_golden

GOLDEN = Path(__file__).resolve().parents[1] / "eval" / "golden"


def test_run_golden(sbr_rules: ProjectRules) -> None:
    results = {r.name: r for r in run_golden(sbr_rules, GOLDEN)}
    assert set(results) == {"domains", "urls", "texts"}
    assert results["domains"].recall == 1.0 and results["domains"].false_positives == 0
    assert all(r.passed for r in results.values()), [
        r.to_dict() for r in results.values() if not r.passed
    ]


def test_set_result_thresholds() -> None:
    assert not SetResult("x", 10, 6, 5, 0, 0.7, 0.0).passed  # 召回不足
    assert not SetResult("x", 10, 10, 5, 1, 0.7, 0.0).passed  # 负样本必须零误报
    assert SetResult("x", 10, 7, 20, 1, 0.7, 0.1).passed  # 文本：误报率 < 10%
    assert SetResult("x", 0, 0, 0, 0, 0.7, 0.0).passed
    assert SetResult("x", 4, 3, 2, 0, 0.7, 0.0).to_dict()["recall"] == 0.75


def test_eval_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ["--rules", "config/projects/sample-brand/keywords.yaml"]
    assert main([*rules, "eval"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["passed"] is True and [s["name"] for s in out["sets"]] == [
        "domains",
        "urls",
        "texts",
    ]
    for name in ("urls.csv", "texts.csv"):
        shutil.copy(GOLDEN / name, tmp_path / name)
    (tmp_path / "domains.csv").write_text(
        "domain,expected,note\nexample.org,match,故意写错\n", encoding="utf-8"
    )
    assert main([*rules, "eval", "--dir", str(tmp_path)]) == 1
    failed = json.loads(capsys.readouterr().out)["sets"][0]
    assert failed["passed"] is False and failed["failures"][0]["value"] == "example.org"
