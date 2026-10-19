from pathlib import Path

import pytest

from opti import organization as org_mod
from opti.organization import (
    Organization,
    OrganizationInvalid,
    load_organization,
    parse_organization,
)
from opti.sdk.http import HttpPolicy, default_user_agent


def test_defaults_are_neutral(tmp_path: Path) -> None:
    org = load_organization(tmp_path / "missing.yaml")
    assert org.short_name == "Open-TI" and org.security_contact is None
    assert org.user_agent("0.1.0") == "Open-TI/0.1.0"


def test_load_and_user_agent(tmp_path: Path) -> None:
    p = tmp_path / "organization.yaml"
    p.write_text(
        "name: Example Development Bank\nshort_name: EDB\nwebsite: https://www.example.org\n"
        "security_contact: mailto:security@example.org\nlegal_statement: 本机构授权本平台进行品牌保护监测。\n",
        encoding="utf-8",
    )
    org = load_organization(p)
    assert org == Organization(
        name="Example Development Bank", short_name="EDB", website="https://www.example.org",
        security_contact="mailto:security@example.org", legal_statement="本机构授权本平台进行品牌保护监测。",
    )  # fmt: skip
    assert org.user_agent("0.2.0") == "Open-TI/0.2.0 (+mailto:security@example.org)"


def test_repository_has_no_hardcoded_institution() -> None:
    root = Path(__file__).resolve().parents[1]
    offenders = []
    paths = [
        *(root / "src").rglob("*.py"),
        *(root / "src").rglob("*.yaml"),
        *(root / "web" / "src").rglob("*.json"),
    ]
    for path in paths:
        if "migrations" in path.parts:
            continue  # 历史迁移保留原样
        text = path.read_text(encoding="utf-8")
        for needle in ("SBR-TI-Monitor", 'server_default="sbr"', "SBR 自有域名证书监控"):
            if needle in text:
                offenders.append(f"{path.relative_to(root)}: {needle}")
    assert offenders == []


def test_takedown_fields(tmp_path: Path) -> None:
    p = tmp_path / "organization.yaml"
    p.write_text(
        "name: Example Organization\ntakedown_sender: abuse-response@example.org\n"
        "legal_statement_en: We are authorized to act on impersonation.\nsignature: Security Team\n",
        encoding="utf-8",
    )
    org = load_organization(p)
    assert org.takedown_sender == "abuse-response@example.org"
    assert org.legal_statement_en.startswith("We are authorized")
    assert org.signature == "Security Team"
    assert load_organization(tmp_path / "missing.yaml").takedown_sender is None


def test_parse_organization_accepts_known_fields() -> None:
    org = parse_organization("name: Acme\nwebsite: null\nsecurity_contact: mailto:s@acme.test\n")
    assert org.name == "Acme" and org.website is None
    assert org.security_contact == "mailto:s@acme.test"


def test_parse_organization_empty_text_is_default() -> None:
    assert parse_organization("") == Organization()


@pytest.mark.parametrize(
    ("text", "field"),
    [("nick: x\n", "nick"), ("name: 1\n", "name"), ('name: "a\\x01b"\n', "name"), ("- a\n", "")],
)
def test_parse_organization_reports_field(text: str, field: str) -> None:
    with pytest.raises(OrganizationInvalid) as e:
        parse_organization(text)
    assert e.value.field == field


def test_current_organization_prefers_runtime_value() -> None:
    try:
        org_mod.set_current(Organization(name="Runtime", security_contact="mailto:r@x.test"))
        assert org_mod.current_organization().name == "Runtime"
        assert default_user_agent().endswith("(+mailto:r@x.test)")
        assert HttpPolicy().user_agent.endswith("(+mailto:r@x.test)")
    finally:
        org_mod.set_current(None)
