from datetime import UTC, datetime

import pytest

from opti.pipeline.reports import month_period


def test_last_finished_month_follows_report_timezone() -> None:
    # 01:10 UTC 在上海已是 10 月 1 日：上一个已结束的月份是 9 月
    now = datetime(2026, 10, 1, 1, 10, tzinfo=UTC)
    assert month_period(now, "Asia/Shanghai") == (
        datetime(2026, 8, 31, 16, tzinfo=UTC),
        datetime(2026, 9, 30, 16, tzinfo=UTC),
    )
    # 同一时刻纽约还是 9 月 30 日：9 月尚未结束，上一个已结束的月份是 8 月
    assert month_period(now, "America/New_York") == (
        datetime(2026, 8, 1, 4, tzinfo=UTC),
        datetime(2026, 9, 1, 4, tzinfo=UTC),
    )


def test_named_month_across_dst_and_year_end() -> None:
    now = datetime(2027, 1, 5, tzinfo=UTC)
    # 11 月 1 日仍是夏令时（UTC−4），12 月 1 日已是冬令时（UTC−5）
    assert month_period(now, "America/New_York", "2026-11") == (
        datetime(2026, 11, 1, 4, tzinfo=UTC),
        datetime(2026, 12, 1, 5, tzinfo=UTC),
    )
    assert month_period(now, "UTC") == (
        datetime(2026, 12, 1, tzinfo=UTC),
        datetime(2027, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize("month", ["2026-13", "2026-9", "202609", "latest"])
def test_rejects_malformed_month(month: str) -> None:
    with pytest.raises(ValueError, match="YYYY-MM"):
        month_period(datetime(2027, 1, 5, tzinfo=UTC), "UTC", month)


def test_rejects_month_not_finished() -> None:
    now = datetime(2026, 10, 15, tzinfo=UTC)
    with pytest.raises(ValueError, match="2026-10"):
        month_period(now, "UTC", "2026-10")  # 未结束的月份生成后会被唯一约束固定为不完整的内容
