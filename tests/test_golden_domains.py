import csv
from pathlib import Path

import pytest

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher

GOLDEN = Path(__file__).resolve().parents[1] / "eval" / "golden" / "domains.csv"


def _rows() -> list[dict[str, str]]:
    with GOLDEN.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_golden_file_has_both_classes() -> None:
    expected = {r["expected"] for r in _rows()}
    assert {"match", "no_match", "official", "known_lookalike"} <= expected


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["domain"])
def test_golden(sbr_rules: ProjectRules, row: dict[str, str]) -> None:
    m = DomainMatcher(sbr_rules.domains).match(row["domain"])
    actual = "no_match" if m is None else m.status
    assert actual == row["expected"], row["note"]
