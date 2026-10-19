"""管理员任务调度只接受五段数字 Cron，避免保存后调度器才发现非法表达式。"""

from __future__ import annotations

import re


def valid_cron(value: str) -> bool:
    fields = value.split()
    if len(fields) != 5 or len(value) > 100:
        return False
    for field, (minimum, maximum) in zip(
        fields, ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6)), strict=True
    ):
        for part in field.split(","):
            if not re.fullmatch(r"(?:\*|\d+(?:-\d+)?)(?:/\d+)?", part):
                return False
            base, _, step = part.partition("/")
            if step and not 1 <= int(step) <= maximum - minimum + 1:
                return False
            if base != "*":
                ends = [int(n) for n in base.split("-")]
                if any(n < minimum or n > maximum for n in ends) or ends[0] > ends[-1]:
                    return False
    return True
