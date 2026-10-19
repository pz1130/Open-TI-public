from typing import Any

import pytest

from opti.core.config import ProjectRules
from opti.core.text_match import TextMatcher
from opti.core.webpages import page_kind
from opti.enrichers.http_probe.enricher import page_features

BASE = {
    "reachable": True,
    "status": 200,
    "url": "https://sbr.example/",
    "final_url": "https://sbr.example/",
    "content_type": "text/html",
}


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"title": "Welcome", "text_excerpt": "Buy this domain"}, "parking"),
        (
            {
                "title": "Welcome",
                "final_url": "https://sedo.com/search/details/?domain=sbr.example",
            },
            "parking",
        ),
        (
            {"title": "Welcome", "final_url": "https://www.afternic.com/forsale/sbr.example"},
            "parking",
        ),
        (
            {
                "title": "SBR login",
                "text_excerpt": "This domain is for sale",
                "has_password_field": True,
                "brand_terms": ["SBR"],
            },
            "parking",
        ),
        ({"title": "SBR business news", "text_excerpt": "SBR reviews houses for sale."}, "website"),
        ({"title": "Houses for sale", "text_excerpt": "Our real estate listings"}, "website"),
        (
            {"title": "SBR Foundation", "text_excerpt": "A charity with the same acronym."},
            "website",
        ),
        (
            {
                "title": "SBR login",
                "has_password_field": True,
                "has_form": True,
                "brand_terms": ["SBR"],
            },
            "phishing",
        ),
        ({"final_url": "https://other-business.org/"}, "redirect"),
        ({"final_url": "https://www.sbr.example/"}, "website"),
        ({"content_type": "application/json"}, "non_html"),
        ({"content_type": "application/pdf"}, "non_html"),
        ({"text_length": 0}, "empty"),
        ({"title": "Just a moment", "status": 403}, "challenge"),
        ({"error": "TimeoutError", "reachable": False}, "unavailable"),
        ({"status": 404}, "unavailable"),
        (
            {"title": "Welcome", "final_url": "https://notgodaddy.com/forsale/sbr.example"},
            "redirect",
        ),
    ],
)
def test_page_kind(changes: dict[str, Any], expected: str) -> None:
    assert page_kind({**BASE, **changes}) == expected


def test_sale_signal_beyond_excerpt_is_retained(sbr_rules: ProjectRules) -> None:
    html = (
        "<html><head><title>Welcome</title></head><body>"
        + "content " * 1000
        + "Buy this domain</body></html>"
    )
    features = page_features(html, TextMatcher(sbr_rules))
    assert len(features["text_excerpt"]) <= 1500
    assert "Buy this domain" not in features["text_excerpt"]
    assert page_kind({**BASE, **features}) == "parking"


def test_visible_browser_text_overrides_hidden_html(sbr_rules: ProjectRules) -> None:
    html = "<html><head><title>SBR</title></head><body><div style='display:none'>Buy this domain</div><script>SBR Login</script></body></html>"
    features = page_features(html, TextMatcher(sbr_rules), visible_text="A real foundation")
    assert features["text_excerpt"] == "A real foundation" and features["parking_signals"] == []
    assert page_kind({**BASE, **features}) == "website"
