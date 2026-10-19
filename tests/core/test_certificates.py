from datetime import UTC, datetime, timedelta

import pytest

from opti.api.routes.certificates import CertificateMonitorIn
from opti.core.certificates import certificate_domain, certificate_expiry, in_scope

NOW = datetime(2026, 10, 14, tzinfo=UTC)


@pytest.mark.parametrize(
    "offset,state,score",
    [
        (timedelta(days=31), "healthy", 0),
        (timedelta(days=30), "expiring", 50),
        (timedelta(days=7), "expiring", 70),
        (timedelta(seconds=1), "expiring", 70),
        (timedelta(0), "expired", 90),
        (timedelta(seconds=-1), "expired", 90),
    ],
)
def test_expiry_boundaries(offset: timedelta, state: str, score: int) -> None:
    data = {"present": True, "not_after": (NOW + offset).isoformat()}
    result = certificate_expiry(data, NOW, 30)
    assert result[0] == state and result[3] == score


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"present": False},
        {"present": True, "not_after": "bad"},
        {"present": True, "not_after": NOW.isoformat(), "error": "TimeoutError"},
    ],
)
def test_unavailable_is_not_expired(data: dict[str, object]) -> None:
    assert certificate_expiry(data, NOW, 30) == ("error", None, None, 0)


def test_scope_validation_and_idna() -> None:
    assert certificate_domain(" WWW.Example.COM. ") == "www.example.com"
    assert certificate_domain("例子.中国") == "xn--fsqu00a.xn--fiqs8s"
    assert in_scope("a.b.example.com", "example.com")
    assert not in_scope("notexample.com", "example.com")
    assert not in_scope("example.com.evil.org", "example.com")
    for raw in [
        "*.example.com",
        "https://example.com",
        "127.0.0.1",
        "bad_name.example",
        "%example.com",
        "example.com:443",
    ]:
        with pytest.raises(ValueError):
            certificate_domain(raw)
    with pytest.raises(ValueError):
        CertificateMonitorIn(root_domain="example.com", known_domains=["example.com.evil.org"])


def test_warn_days_are_configurable() -> None:
    assert (
        certificate_expiry(
            {"present": True, "not_after": (NOW + timedelta(days=10)).isoformat()}, NOW, 5
        )[0]
        == "healthy"
    )
