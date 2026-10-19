import csv
from pathlib import Path

import pytest

from opti.core.config import ProjectRules
from opti.core.urls import UrlMatcher

GOLDEN = Path(__file__).resolve().parents[1] / "eval" / "golden" / "urls.csv"


def _rows() -> list[dict[str, str]]:
    with GOLDEN.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_golden_file_has_all_classes() -> None:
    assert {r["expected"] for r in _rows()} == {"domain", "url", "none"}


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["url"])
def test_golden(sbr_rules: ProjectRules, row: dict[str, str]) -> None:
    um = UrlMatcher(sbr_rules)
    m = um.match(row["url"])
    actual = "none" if m is None or m.kind is None else m.kind
    assert actual == row["expected"], row["note"]
    if actual != "none":
        assert um.could_match(row["url"]), "预过滤不能漏报"
