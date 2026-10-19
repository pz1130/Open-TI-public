from pathlib import Path

import pytest
from pydantic import ValidationError

from opti.core.vendors import PartyMatcher, VendorList, host_key, load_vendors, normalize_org
from opti.organization import Organization

REPO = Path(__file__).resolve().parents[2]
ORG = Organization(name="Example Development Bank", short_name="EDB")
VENDORS = VendorList.model_validate({"vendors": [
    {"id": "acme", "name": "Acme Holdings Ltd", "aliases": ["ACME Cloud"], "domains": ["acme.example"], "tier": "critical", "owner": "IT"},
    {"id": "abc", "name": "AB", "tier": "normal"},
    {"id": "dup", "name": "Example Development Bank", "tier": "high"},
]})  # fmt: skip


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("Acme Inc.", "acme"),
        ("ACME, Incorporated", "acme"),
        ("Acme Holdings Ltd", "acme"),
        ("Banco Ejemplo S.A.", "banco ejemplo"),
        ("Müller & Söhne GmbH", "müller and söhne"),
        ("示例科技股份有限公司", "示例科技"),
        ("  Ａｃｍｅ  ", "acme"),
        ("The Group", "the"),
    ],
)
def test_normalize_org(raw: str, want: str) -> None:
    assert normalize_org(raw) == want


def test_host_key() -> None:
    assert host_key("www.acme.com") == "acme.com"
    assert host_key("https://portal.acme.co.uk/") is None
    assert host_key("acme.example") == "acme.example"
    assert host_key("Acme Inc") is None


def test_exact_match_and_priority() -> None:
    m = PartyMatcher(ORG, ["edb.example"], VENDORS)
    [hit] = m.match("ACME Cloud", None)
    assert hit.party.id == "acme" and hit.how == "name" and hit.party.tier == "critical"
    assert m.match("Acme Cloud Services", None) == []
    assert m.match("AB", None) == []
    [by_domain] = m.match("Some Subsidiary", "mail.acme.example")
    assert by_domain.how == "domain" and by_domain.detail == "acme.example"
    assert m.match("Example Development Bank Ltd", None)[0].party.kind == "self"
    assert m.match("edb.example", None)[0].party.kind == "self"


def test_default_organization_is_not_matched() -> None:
    assert PartyMatcher(Organization(), [], VendorList()).match("Open-TI user", None) == []


def test_load_vendors(tmp_path: Path) -> None:
    assert load_vendors(tmp_path / "missing.yaml") == VendorList()
    assert load_vendors(REPO / "config" / "vendors.yaml").vendors
    p = tmp_path / "vendors.yaml"
    p.write_text("vendors:\n  - {id: a, name: A Corp, tier: gold}\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_vendors(p)
    p.write_text(
        "vendors:\n  - {id: a, name: A Corp}\n  - {id: a, name: B Corp}\n", encoding="utf-8"
    )
    with pytest.raises(ValidationError):
        load_vendors(p)
