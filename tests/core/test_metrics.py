from datetime import UTC, datetime

from opti.core.metrics import (
    MttdStat,
    ct_event_time,
    median,
    parse_time,
    registration_time,
    source_group,
    summarize,
)

T = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


def test_parse_time() -> None:
    assert parse_time(T.timestamp()) == T and parse_time(int(T.timestamp())) == T
    assert parse_time("2026-10-02T08:00:00") == T and parse_time("2026-10-02T16:00:00+08:00") == T
    assert parse_time("2026-10-02T08:00:00Z") == T
    for bad in (None, "", "yesterday", 0, -5, True, {"x": 1}, float("inf"), float("nan"), 10**100):
        assert parse_time(bad) is None


def test_event_times() -> None:
    assert ct_event_time("certstream", {"cert": {"seen": T.timestamp(), "not_before": 1}}) == T
    assert ct_event_time("certstream", {"cert": {"not_before": int(T.timestamp())}}) == T
    assert (
        ct_event_time(
            "crtsh",
            {"entry_timestamp": "2026-10-02T08:00:00.000", "not_before": "2026-10-01T00:00:00"},
        )
        == T
    )
    assert ct_event_time("crtsh", {"not_before": "2026-10-02T08:00:00"}) == T
    assert (
        ct_event_time("nrd", {"cert": {"seen": 1}}) is None
        and ct_event_time("certstream", {"cert": "x"}) is None
    )
    assert (
        registration_time(
            {"rdap": {"data": {"registration": "2026-10-02T08:00:00Z"}, "fetched_at": "x"}}
        )
        == T
    )
    assert registration_time({"rdap": {"data": {}}}) is None and registration_time({}) is None
    assert [source_group(c) for c in ("certstream", "crtsh", "nrd", "dnstwist", "urlhaus")] == [
        "ct",
        "ct",
        "nrd",
        "nrd",
        None,
    ]


def test_summarize() -> None:
    assert median([]) is None and median([3.0, 1.0, 2.0]) == 2.0 and median([0.5, 2.0]) == 1.25
    stats = summarize({"ct": [0.5, 2.0], "nrd": [20.0]})
    assert stats == [
        MttdStat("ct", 2, 1.25, 0.5, 1.0),
        MttdStat("nrd", 1, 20.0, 1.0, 24.0),
    ]
    assert summarize({}) == [
        MttdStat("ct", 0, None, None, 1.0),
        MttdStat("nrd", 0, None, None, 24.0),
    ]
