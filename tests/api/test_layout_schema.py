from typing import Any

import pytest
from pydantic import ValidationError

from opti.api.schemas import LayoutSpec


def _layout(*widgets: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"version": 1, "days": 30, "widgets": list(widgets), **extra}


def _widget(wid: str = "a1", **extra: Any) -> dict[str, Any]:
    return {"id": wid, "type": "trend", "x": 0, "y": 0, "w": 8, "h": 4,
            "params": {"days": None, "category": "phishing_site", "limit": 5, "flag": True},
            **extra}  # fmt: skip


def test_valid_layout_round_trips() -> None:
    spec = LayoutSpec.model_validate(_layout(_widget(), _widget("b2", x=8, w=4)))
    assert [w.id for w in spec.widgets] == ["a1", "b2"]
    assert spec.widgets[0].params == {
        "days": None, "category": "phishing_site", "limit": 5, "flag": True,
    }  # fmt: skip


@pytest.mark.parametrize(
    "layout",
    [
        _layout(_widget(), _widget()),  # 重复 id
        _layout(_widget(x=6, w=8)),  # x + w 超过 12 列
        _layout(_widget(h=25)),
        _layout(_widget(id="bad id")),
        _layout(_widget(type="Trend")),
        _layout(_widget(params={"BAD": 1})),
        _layout(_widget(params={"k": 1.5})),  # 只允许 null / 布尔 / 整数 / 字符串
        _layout(_widget(params={"k": "x" * 65})),
        _layout(_widget(params={f"k_{c}": 1 for c in "abcdefghi"})),  # 超过 8 个参数
        _layout(*[_widget(f"w{i}") for i in range(31)]),
        _layout(_widget(), version=2),
        _layout(_widget(), days=0),
        _layout(_widget(), extra=1),
        {"version": 1, "days": 30, "widgets": [{**_widget(), "params": None}]},
    ],
)
def test_invalid_layouts_are_rejected(layout: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        LayoutSpec.model_validate(layout)


def test_layout_size_is_capped() -> None:
    long = "x" * 64
    widgets = [_widget(f"w{i}", params={f"k_{c}": long for c in "abcdefgh"}) for i in range(30)]
    with pytest.raises(ValidationError, match="layout too large"):
        LayoutSpec.model_validate(_layout(*widgets))
