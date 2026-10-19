import csv
import json
from pathlib import Path

import pytest

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.core.domains import to_ascii

GOLDEN = Path(__file__).resolve().parents[2] / "eval" / "golden" / "domains.csv"


@pytest.fixture(scope="module")
def matcher(sbr_rules: ProjectRules) -> DomainMatcher:
    return DomainMatcher(sbr_rules.domains)


def test_to_ascii_roundtrip() -> None:
    assert to_ascii("ѕbr-loans.com") == "xn--br-loans-jhh.com"
    assert to_ascii("sbr-loans.com") == "sbr-loans.com"


EXTRA_POSITIVES = [
    "SBR-LOANS.COM",
    "*.sbr-loans.com",
    "orbit-bank-invest.com",  # 连字符拆开长品牌词
    "orbibank.com",  # 删除一个字符
    "samplebrnd.org",  # 删除一个字符
    "samp1ebrand.org",  # 替换一个字符
    "sаmplеbrand.com",  # 西里尔 а、е
    "xn--br-loans-jhh.com",
    "orbit-loan.com",  # 受限品牌词（Task 0）
]


def test_prefilter_never_drops_a_match(matcher: DomainMatcher) -> None:
    with GOLDEN.open(encoding="utf-8") as f:
        golden = [r["domain"] for r in csv.DictReader(f)]
    for d in [*golden, *EXTRA_POSITIVES]:
        if matcher.match(d) is not None:
            assert matcher.could_match(d), d


@pytest.mark.parametrize("domain", ["example.org", "tidysitespro.com", "88cuci.website"])
def test_prefilter_rejects_unrelated(matcher: DomainMatcher, domain: str) -> None:
    assert not matcher.could_match(domain)


def test_to_dict_is_json_serializable(matcher: DomainMatcher) -> None:
    m = matcher.match("sbr-loans.com")
    assert m is not None
    d = json.loads(json.dumps(m.to_dict()))
    assert d["status"] == "match" and d["registered"] == "sbr-loans.com"
    assert {r["reason"] for r in d["reasons"]} >= {"brand_label", "fraud_affix"}
