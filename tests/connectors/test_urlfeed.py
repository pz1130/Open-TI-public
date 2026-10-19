from opti.connectors.urlfeed import UrlFeedScanner
from opti.core.config import ProjectRules
from opti.sdk.plan import build_query_plan


def test_scan_filters_dedupes_and_builds_payload(sbr_rules: ProjectRules) -> None:
    scanner = UrlFeedScanner("openphish", sbr_rules)
    entries = [
        ("https://sbr-loans.com/login?utm_source=x", {"confirmed": True}),
        ("https://sbr-loans.com/login", {"confirmed": True}),  # 规范化后重复
        ("https://sites.google.com/view/sbr-grants", {"confirmed": True, "target": "SBR"}),
        ("https://example.org/news", {"confirmed": True}),
        ("https://sbr.int/careers", {"confirmed": True}),
        ("not a url at all", {"confirmed": True}),
    ]
    items = list(scanner.scan(entries, build_query_plan(sbr_rules)))
    assert [(i.source_item_id, i.payload["kind"]) for i in items] == [
        ("https://sbr-loans.com/login", "domain"),
        ("https://sites.google.com/view/sbr-grants", "url"),
    ]
    first = items[0]
    assert first.connector_id == "openphish" and first.url == "https://sbr-loans.com/login"
    assert first.payload["feed_url"] == "https://sbr-loans.com/login"
    assert first.payload["intel"] == {"source": "openphish", "confirmed": True}
    assert items[1].payload["intel"]["target"] == "SBR"
    assert first.project_ids == ("sample-brand-protection",)
    assert scanner.stats == {"seen": 6, "matched": 2, "invalid": 1}


def test_dedup_across_lists_and_reset(sbr_rules: ProjectRules) -> None:
    scanner = UrlFeedScanner("phishing_db", sbr_rules)
    plan = build_query_plan(sbr_rules)
    entries = [("http://sbr-loans.com/", {"confirmed": True})]
    assert len(list(scanner.scan(entries, plan))) == 1
    assert list(scanner.scan(entries, plan)) == []
    scanner.reset()
    assert len(list(scanner.scan(entries, plan))) == 1
    assert scanner.stats["matched"] == 1


def test_userinfo_context_without_credentials(sbr_rules: ProjectRules) -> None:
    scanner = UrlFeedScanner("openphish", sbr_rules)
    item = next(
        scanner.scan(
            [
                ("https://personal-sbr.int:secret-password@evil.top/login", {"confirmed": True}),
            ],
            build_query_plan(sbr_rules),
        )
    )
    assert item.url == "https://evil.top/login"
    assert item.payload["match_input"] == "https://sbr@evil.top/login"
    assert "secret-password" not in str(item)
    assert "personal" not in str(item)
