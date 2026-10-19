import json
from datetime import UTC, datetime, timedelta
from typing import Any

import stix2

from opti.core.stix import TLP, StixEvidence, StixFinding, build_bundle

T0 = datetime(2026, 10, 1, 8, tzinfo=UTC)
BASE = "https://ti.example"


def _f(fid: int, category: str, etype: str, value: str, **change: Any) -> StixFinding:
    args: dict[str, Any] = {
        "finding_id": fid, "category": category, "severity": "high", "score": 72, "entity_type": etype,
        "entity_value": value, "first_seen": T0, "last_seen": T0 + timedelta(hours=5), "observations": 3,
        "confirmed": False, "match": {"reasons": [{"reason": "brand_label"}, {"reason": "fraud_affix"}]},
    }  # fmt: skip
    args.update(change)
    return StixFinding(**args)


def _bundle(*findings: StixFinding, tlp: str = "amber") -> dict[str, Any]:
    return build_bundle(
        findings, project="demo", organization="Example Development Bank", base_url=BASE, tlp=tlp
    )


def _by_type(bundle: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == kind]


def test_domain_indicator_sighting_and_evidence() -> None:
    ev = StixEvidence(11, "image/png", "a" * 64)
    b = _bundle(_f(1, "typosquat_domain", "domain", "sbr-loans.com", evidence=(ev,)))
    stix2.parse(json.dumps(b), allow_custom=False)  # 能被官方库解析
    [ind] = _by_type(b, "indicator")
    assert ind["pattern"] == "[domain-name:value = 'sbr-loans.com']"
    assert ind["indicator_types"] == ["anomalous-activity"] and ind["confidence"] == 72
    assert ind["labels"] == ["typosquat_domain"] and ind["object_marking_refs"] == [
        stix2.TLP_AMBER.id
    ]
    assert ind["description"] == "brand_label, fraud_affix"
    [sighting] = _by_type(b, "sighting")
    assert sighting["sighting_of_ref"] == ind["id"] and sighting["count"] == 3
    [ap] = _by_type(b, "attack-pattern")
    assert ap["external_references"][0]["external_id"] == "T1583.001"
    rels = {
        (r["relationship_type"], r["target_ref"].split("--")[0])
        for r in _by_type(b, "relationship")
    }
    assert rels == {
        ("based-on", "domain-name"),
        ("related-to", "attack-pattern"),
        ("related-to", "artifact"),
    }
    [art] = _by_type(b, "artifact")
    assert art["url"] == f"{BASE}/api/v1/evidence/11/content" and art["hashes"] == {
        "SHA-256": "a" * 64
    }
    names = {o["name"] for o in _by_type(b, "identity")}
    assert names == {"Open-TI", "Example Development Bank"}


def test_ids_are_deterministic() -> None:
    f = _f(1, "phishing_site", "url", "https://sbr-loans.com/login")
    ids = lambda b: {o["id"] for o in b["objects"]}  # noqa: E731
    assert ids(_bundle(f)) == ids(_bundle(f))
    other = build_bundle([f], project="other", organization="x", base_url=BASE)
    assert {o["id"] for o in _by_type(_bundle(f), "indicator")} != {
        o["id"] for o in _by_type(other, "indicator")
    }


def test_indicator_pattern_escaping() -> None:
    url = "https://evil.example/a'b\\c?x=1"
    b = _bundle(_f(2, "phishing_site", "url", url, confirmed=True))
    stix2.parse(json.dumps(b), allow_custom=False)
    [ind] = _by_type(b, "indicator")
    assert ind["pattern"] == "[url:value = 'https://evil.example/a\\'b\\\\c?x=1']"
    assert ind["indicator_types"] == ["malicious-activity"]
    [ap] = _by_type(b, "attack-pattern")
    assert ap["external_references"][0]["external_id"] == "T1566"


def test_ip_and_invalid_ip() -> None:
    b = _bundle(
        _f(3, "reported_phishing", "ip", "2001:db8::1"),
        _f(4, "reported_phishing", "ip", "not-an-ip"),
    )
    [ind] = _by_type(b, "indicator")
    assert ind["pattern"] == "[ipv6-addr:value = '2001:db8::1']"
    assert [r["name"] for r in _by_type(b, "report")] == [
        "reported_phishing: not-an-ip"
    ]  # 无法构成指标的退化为报告


def test_reports_ransomware_and_vulnerability() -> None:
    news = _f(5, "fraud_scam", "document", "cluster:9", match={
        "document": {"title": "Fake EDB loan offers", "url": "https://news.example/a", "source_name": "Example News"},
        "contexts": ["Jane Roe said the EDB loan offer is fake"],
    })  # fmt: skip
    ransom = _f(6, "ransomware_mention", "leak_post", "ransom:akira:acme",
                match={"post": {"group": "akira", "victim": "Acme Holdings"}})  # fmt: skip
    vuln = _f(7, "vulnerability", "cve", "CVE-2026-12345", match={
        "kev": {"cve": "CVE-2026-12345", "name": "EdgeGate VPN Bypass"},
        "software": [{"id": "vpn", "vendor": "Example Networks", "products": ["EdgeGate VPN"], "owner": "网络组"}],
    })  # fmt: skip
    b = _bundle(news, ransom, vuln)
    stix2.parse(json.dumps(b), allow_custom=False)
    reports = {r["name"]: r for r in _by_type(b, "report")}
    assert reports["Fake EDB loan offers"]["external_references"] == [
        {"source_name": "Example News", "url": "https://news.example/a"}
    ]
    [actor] = _by_type(b, "threat-actor")
    assert actor["name"] == "akira"
    victim = next(o for o in _by_type(b, "identity") if o["name"] == "Acme Holdings")
    assert any(
        r["relationship_type"] == "targets" and r["target_ref"] == victim["id"]
        for r in _by_type(b, "relationship")
    )
    [v] = _by_type(b, "vulnerability")
    assert v["name"] == "CVE-2026-12345" and v["external_references"] == [
        {"source_name": "cve", "external_id": "CVE-2026-12345"}
    ]


def test_no_personal_or_inventory_data() -> None:
    exposure = _f(8, "credential_exposure", "breach", "hibp:ExampleBreach",
                  match={"accounts": ["jane.roe@edb.example"], "breach": "ExampleBreach"})  # fmt: skip
    news = _f(9, "brand_mention", "document", "cluster:1",
              match={"document": {"title": "EDB news"}, "contexts": ["Jane Roe, CFO of EDB"]})  # fmt: skip
    vuln = _f(10, "vulnerability", "cve", "CVE-2026-1", match={"kev": {"cve": "CVE-2026-1"},
              "software": [{"vendor": "Example Networks", "products": ["EdgeGate VPN"], "owner": "网络组"}]})  # fmt: skip
    text = json.dumps(_bundle(exposure, news, vuln), ensure_ascii=False)
    for secret in ("jane.roe@edb.example", "Jane Roe", "网络组", "EdgeGate"):
        assert secret not in text


def test_tlp_choice() -> None:
    b = _bundle(_f(1, "typosquat_domain", "domain", "sbr-loans.com"), tlp="green")
    assert {o["id"] for o in _by_type(b, "marking-definition")} == {TLP["green"].id}
    assert _by_type(b, "indicator")[0]["object_marking_refs"] == [stix2.TLP_GREEN.id]


def test_ambiguous_email_spoofing_has_no_attack_pattern() -> None:
    b = _bundle(_f(11, "email_spoofing", "domain", "mail.example"))
    assert _by_type(b, "attack-pattern") == []


def test_impersonation_account_is_not_an_indicator() -> None:
    from opti.core.stix import INDICATOR_CATEGORIES

    assert "impersonation_account" not in INDICATOR_CATEGORIES
