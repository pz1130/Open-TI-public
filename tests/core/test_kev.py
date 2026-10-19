from datetime import date
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opti.core.kev import (
    KevError,
    SoftwareList,
    SoftwareMatcher,
    digest,
    kev_payload,
    load_software,
    normalize_name,
    parse_kev,
)
from opti.core.scoring import Category, Severity, VulnFacts, score_vulnerability, vuln_reasons
from opti.settings import Settings

RAW = {
    "cveID": "CVE-2026-12345", "vendorProject": "Example Networks", "product": "EdgeGate VPN",
    "vulnerabilityName": "Example Networks EdgeGate VPN Authentication Bypass", "dateAdded": "2026-10-01",
    "shortDescription": "An  authentication bypass\nallows remote attackers to log in.",
    "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2026-10-22",
    "knownRansomwareCampaignUse": "Known", "notes": "https://vendor.example/advisory", "cwes": ["CWE-287", "bogus"],
}  # fmt: skip


def _payload(**change: Any) -> dict[str, Any]:
    payload = kev_payload({**RAW, **change})
    assert payload is not None
    return payload


def test_kev_payload_roundtrip() -> None:
    k = parse_kev(_payload())
    assert (k.cve, k.vendor, k.product) == ("CVE-2026-12345", "Example Networks", "EdgeGate VPN")
    assert (
        k.date_added == date(2026, 10, 1)
        and k.due_date == date(2026, 10, 22)
        and k.ransomware is True
    )
    assert (
        k.description == "An authentication bypass allows remote attackers to log in."
        and k.cwes == ("CWE-287",)
    )
    assert parse_kev(_payload(knownRansomwareCampaignUse="Unknown")).ransomware is False
    assert parse_kev(_payload(dueDate=None)).due_date is None
    assert len(digest(_payload())) == 16 and digest(_payload()) != digest(_payload(notes="changed"))


@pytest.mark.parametrize(
    "change",
    [
        {"cveID": "CVE-26-1"},
        {"cveID": None},
        {"dateAdded": "yesterday"},
        {"vendorProject": " "},
        {"product": 5},
    ],
)
def test_kev_payload_rejects_bad_entries(change: dict[str, Any]) -> None:
    assert kev_payload({**RAW, **change}) is None


def test_parse_kev_rejects_tampered_payload() -> None:
    with pytest.raises(KevError):
        parse_kev({})
    with pytest.raises(KevError):
        parse_kev({"kev": {**_payload()["kev"], "cve": "CVE-2026-1; drop"}})
    assert (
        parse_kev({"kev": {**_payload()["kev"], "ransomware": "true"}}).ransomware is False
    )  # 只认布尔值


def test_software_matching() -> None:
    inventory = SoftwareList.model_validate({"software": [
        {"id": "vpn", "vendor": "Example Networks", "vendor_aliases": ["ExampleNet"],
         "products": ["EdgeGate VPN", "EdgeGate"], "tier": "critical", "exposed": True, "owner": "网络组"},
        {"id": "vpn-lab", "vendor": "Example Networks", "products": ["EdgeGate VPN"]},
    ]})  # fmt: skip
    m = SoftwareMatcher(inventory)
    assert [s.id for s in m.match("EXAMPLE NETWORKS", "EdgeGate-VPN")] == ["vpn", "vpn-lab"]
    assert [s.id for s in m.match("ExampleNet", "edgegate")] == ["vpn"]
    assert m.match("Example Networks", "EdgeGate VPN Manager") == []  # 不做模糊匹配
    assert normalize_name("  Ｅxample_Networks, Inc. ") == "example networks inc"
    assert SoftwareMatcher(SoftwareList()).empty and not m.empty


def test_software_list_validation(tmp_path: Path) -> None:
    bad = [
        [{"id": "a", "vendor": "X", "products": []}],
        [{"id": "a", "vendor": "X", "products": ["--"]}],
        [
            {"id": "a", "vendor": "X", "products": ["P"]},
            {"id": "a", "vendor": "Y", "products": ["Q"]},
        ],
        [{"id": "a", "vendor": "X", "products": ["P"], "tier": "urgent"}],
        [{"id": "A B", "vendor": "X", "products": ["P"]}],
    ]
    for software in bad:
        with pytest.raises(ValidationError):
            SoftwareList.model_validate({"software": software})
    assert load_software(tmp_path / "missing.yaml") == SoftwareList()
    assert load_software(Path("config/software.yaml")).software == ()  # 仓库自带的是空清单
    assert Settings().software_path == Path("config/software.yaml")
    assert Settings.from_env({"OPTI_SOFTWARE": "/etc/opti/software.yaml"}).software_path == Path(
        "/etc/opti/software.yaml"
    )


@pytest.mark.parametrize(
    ("facts", "value", "severity"),
    [
        (VulnFacts("critical", True, True, 2), 85, Severity.CRITICAL),
        (VulnFacts("high", False, False, 10), 55, Severity.MEDIUM),
        (VulnFacts("high", False, True, 10), 65, Severity.HIGH),
        (VulnFacts("normal", False, False, 100), 35, Severity.LOW),
        (VulnFacts("normal", False, False, 800), 20, Severity.LOW),
        (VulnFacts("critical", False, False, 800), 40, Severity.MEDIUM),
    ],
)
def test_score_vulnerability(facts: VulnFacts, value: int, severity: Severity) -> None:
    s = score_vulnerability(facts)
    assert (s.value, s.severity, s.category) == (value, severity, Category.VULNERABILITY)


def test_vuln_reasons() -> None:
    assert vuln_reasons(VulnFacts("critical", True, True, 2)) == [
        "critical_software", "internet_facing", "ransomware_use", "recently_added",
    ]  # fmt: skip
    assert vuln_reasons(VulnFacts("normal", False, False, 800)) == [
        "inventory_software",
        "old_entry",
    ]
