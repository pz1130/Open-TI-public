from opti.core.config import ProjectRules
from opti.core.watcher import compare, parse_export


def test_parse_export_variants() -> None:
    csv_text = (
        "﻿id,domain_name,created_at\n1,SBR-Loans.COM,2026-10-01\n2,sbr-login.top.,2026-10-02\n"
    )
    assert parse_export(csv_text) == ["sbr-loans.com", "sbr-login.top"]
    semi = "Domain;Fuzzer\nsbr-pay.top;addition\nsbr-pay.top;homoglyph\n"
    assert parse_export(semi) == ["sbr-pay.top"]
    plain = "# Watcher DNS Finder export\nhttps://sbr-portal.xyz/login\nsbr-grants.top extra-column\nnot a domain!!\n\n"
    assert parse_export(plain) == ["sbr-grants.top", "sbr-portal.xyz"]
    assert parse_export("") == [] and parse_export("domain\n") == []
    no_header = "sbr-a.top,2026-10-01\nsbr-b.top,2026-10-02\n"
    assert parse_export(no_header) == ["sbr-a.top", "sbr-b.top"]


def test_compare(sbr_rules: ProjectRules) -> None:
    ours = {"sbr-loans.com", "secure.sbr-pay.top", "sbr-only-ours.top"}
    theirs = [
        "sbr-loans.com",
        "sbr-pay.top",
        "sbr-missed.top",
        "sbr-old.top",
        "portal.sbr.int",
        "sbrbank.com",
    ]
    result = compare(ours, theirs, rules=sbr_rules, elsewhere={"sbr-old.top"})
    assert result.both == ["sbr-loans.com", "sbr-pay.top"]  # 同一可注册域也算一致
    assert result.ours_only == ["sbr-only-ours.top"]
    assert result.watcher_only == [
        {"domain": "sbr-missed.top", "status": "not_found"},
        {"domain": "sbr-old.top", "status": "found_outside_window"},
        {"domain": "portal.sbr.int", "status": "protected"},  # 官方域名：不算漏报
        {"domain": "sbrbank.com", "status": "protected"},  # 已知合法相似方
    ]
    d = result.to_dict()
    assert d["summary"] == {"both": 2, "ours_only": 1, "watcher_only": 4, "missed": 1}
