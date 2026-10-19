from datetime import UTC, datetime

import pytest

from opti.core.exposure import (
    BreachInfo,
    ExposureError,
    breach_catalog,
    exposure_payload,
    group_by_breach,
    parse_exposure,
)

OFFICIAL = ("example.org",)
CATALOG_DOC = [
    {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "AddedDate": "2013-12-04T00:00:00Z",
     "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"], "IsVerified": True,
     "IsFabricated": False, "IsSensitive": False, "IsSpamList": False},
    {"Name": "NewLeak", "Title": "New Leak 2026", "BreachDate": "2026-08-01", "AddedDate": "2026-10-01T00:00:00Z",
     "DataClasses": ["Email addresses"], "IsVerified": False, "IsStealerLog": True},
    "garbage",
    {"Title": "no name"},
]  # fmt: skip


def test_breach_catalog() -> None:
    cat = breach_catalog(CATALOG_DOC)
    assert set(cat) == {"Adobe", "NewLeak"}
    assert cat["Adobe"].data_classes == (
        "Email addresses",
        "Password hints",
        "Passwords",
        "Usernames",
    )
    assert cat["NewLeak"].stealer_log is True and cat["NewLeak"].verified is False
    unknown = BreachInfo.unknown("Mystery")
    assert unknown.title == "Mystery" and unknown.verified is False and unknown.data_classes == ()


def test_group_by_breach_rejects_bad_aliases() -> None:
    data = {
        "Alice": ["Adobe", "NewLeak"], "bob": ["Adobe"], "x@evil.org": ["Adobe"], "line\nbreak": ["Adobe"],
        "a" * 65: ["Adobe"], "carol": "not-a-list", "dave": ["", 3],
    }  # fmt: skip
    assert group_by_breach(data, "example.org") == {
        "Adobe": ["alice@example.org", "bob@example.org"],
        "NewLeak": ["alice@example.org"],
    }


def _payload(**kw: object) -> dict[str, object]:
    info = breach_catalog(CATALOG_DOC)["Adobe"]
    base = dict(source="hibp", kind="breach", key="hibp:example.org:Adobe", domain="example.org", info=info,
                title=info.title, affected=2, accounts=["alice@example.org", "bob@example.org"])  # fmt: skip
    return exposure_payload(**{**base, **kw})["exposure"]  # type: ignore[arg-type]


def test_parse_exposure_round_trip_and_public_view() -> None:
    ex = parse_exposure(_payload(), OFFICIAL)
    assert ex.key == "hibp:example.org:Adobe" and ex.accounts == (
        "alice@example.org",
        "bob@example.org",
    )
    facts = ex.facts(datetime(2026, 10, 3, tzinfo=UTC))
    assert facts.kind == "breach" and facts.affected == 2 and "Passwords" in facts.data_classes
    assert facts.age_days is not None and facts.age_days > 12 * 365
    public = ex.public()
    assert public["affected"] == 2 and "accounts" not in public and "alice" not in str(public)


@pytest.mark.parametrize(
    "kw",
    [
        {"domain": "other.org", "key": "hibp:other.org:Adobe"},  # 不是官方域名
        {"key": "hibp:example.org"},  # key 格式不对
        {"key": "hudsonrock:example.org", "kind": "breach"},  # key 与 kind 不匹配
        {"kind": "rumour"},
        {"accounts": ["alice@example.org"] * 5001},
    ],
)
def test_parse_exposure_rejects(kw: dict[str, object]) -> None:
    with pytest.raises(ExposureError):
        parse_exposure(_payload(**kw), OFFICIAL)


def test_foreign_accounts_are_dropped_and_subdomains_allowed() -> None:
    ex = parse_exposure(
        _payload(accounts=["alice@example.org", "eve@evil.org", "BAD", "Bob@Example.org"]), OFFICIAL
    )
    assert ex.accounts == ("alice@example.org", "bob@example.org")
    sub = parse_exposure(
        _payload(
            domain="mail.example.org",
            key="hibp:mail.example.org:Adobe",
            accounts=["x@mail.example.org"],
        ),
        OFFICIAL,
    )
    assert sub.accounts == ("x@mail.example.org",)
