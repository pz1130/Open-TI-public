from copy import deepcopy

import pytest

from opti.core.alert_fingerprint import changed, fingerprint


def facts():  # type: ignore[no-untyped-def]
    return {
        "dns": {
            "data": {"a": ["8.8.8.8", "1.1.1.1"], "mx": [], "error": None},
            "fetched_at": "old",
        },
        "tls": {"data": {"sha256": "cert-one", "not_after": "2030-01-01"}},
        "http_probe": {
            "data": {
                "status": 200,
                "title": "Sign in",
                "has_password_field": False,
                "final_url": "https://example.com/login?utm_source=one",
                "html_sha256": "old",
            }
        },
        "screenshot": {"data": {"sha256": "image-one", "captured_at": "old"}},
    }


def test_noise_ordering_tracking_and_failed_probes_do_not_restore() -> None:
    data = facts()
    baseline = fingerprint("phishing_site", "high", {"reasons": [{"reason": "old"}]}, data)
    latest = deepcopy(data)
    latest["dns"]["data"]["a"].reverse()
    latest["dns"]["fetched_at"] = "new"
    page = latest["http_probe"]["data"]
    page.update(
        title=" Sign   in ",
        html_sha256="dynamic-page",
        final_url="https://example.com/login?utm_source=two#banner",
    )
    latest["screenshot"]["data"].update(sha256="image-two", captured_at="new")
    assert not changed(
        baseline, fingerprint("phishing_site", "high", {"reasons": [{"reason": "new"}]}, latest)
    )
    latest["dns"]["data"] = {"error": "TimeoutError"}
    latest["tls"]["data"] = {"error": "TimeoutError"}
    latest["http_probe"]["data"] = {"status": 503, "title": "Unavailable"}
    assert not changed(baseline, fingerprint("phishing_site", "high", {}, latest))


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("dns", "a", ["9.9.9.9"]),
        ("dns", "mx", ["10 evil.example"]),
        ("tls", "sha256", "cert-two"),
        ("tls", "not_after", "2031-01-01"),
        ("http_probe", "title", "Apply for loan"),
        ("http_probe", "has_password_field", True),
        ("http_probe", "final_url", "https://evil.example/collect"),
    ],
)
def test_important_facts_restore(section: str, key: str, value: object) -> None:
    data = facts()
    baseline = fingerprint("phishing_site", "high", {}, data)
    data[section]["data"][key] = value
    assert changed(baseline, fingerprint("phishing_site", "high", {}, data))


def test_code_changes_compare_hash_and_location_without_secret_values() -> None:
    scan = {
        "secrets": [
            {"sha256": "digest1", "file": ".env", "rule": "key", "prefix": "secret", "date": "old"}
        ]
    }
    baseline = fingerprint("code_secret", "high", {"scan": scan}, {})
    scan["secrets"][0].update(date="new", prefix="other")
    assert not changed(baseline, fingerprint("code_secret", "high", {"scan": scan}, {}))
    scan["secrets"][0]["sha256"] = "digest2"
    assert changed(baseline, fingerprint("code_secret", "high", {"scan": scan}, {}))
    assert "secret" not in str(baseline["code.secrets"])
