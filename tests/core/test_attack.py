import json
from pathlib import Path

from opti.core.attack import candidate_tags, catalog


def test_catalog_is_from_versioned_stix_and_tags_are_candidates() -> None:
    source = Path(__file__).resolve().parents[2] / "src/opti/core/attack_catalog.json"
    data = json.loads(source.read_text(encoding="utf-8"))
    assert "enterprise-attack-19.2.json" in data["source"]
    assert len(data["source_sha256"]) == 64
    assert set(catalog()) == {"T1566", "T1583.001", "T1585.001"}
    assert candidate_tags("phishing_site") == [
        {
            "id": "T1566",
            "name": "Phishing",
            "tactics": ["initial-access"],
            "url": "https://attack.mitre.org/techniques/T1566/",
        }
    ]
    assert candidate_tags("typosquat_domain")[0]["tactics"] == ["resource-development"]


def test_unrelated_and_ambiguous_categories_have_no_technique() -> None:
    for category in ("email_spoofing", "brand_mention", "vulnerability", "credential_exposure"):
        assert candidate_tags(category) == []


def test_impersonation_account_maps_to_social_media_accounts() -> None:
    assert candidate_tags("impersonation_account") == [
        {
            "id": "T1585.001",
            "name": "Social Media Accounts",
            "tactics": ["resource-development"],
            "url": "https://attack.mitre.org/techniques/T1585/001/",
        }
    ]
