"""按来源 IP 的滑动窗口限流（设计文档 19）。研判接口是单进程部署，计数放在进程内，重启后清零。

按账号的锁定（连续 5 次失败锁 15 分钟）防的是猜某一个账号；这里防的是同一来源轮流猜很多账号。
"""

from __future__ import annotations

import math
from collections import OrderedDict, deque
from datetime import datetime, timedelta


class SlidingWindow:
    def __init__(self, limit: int, window: timedelta, *, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[datetime]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._hits)

    def __contains__(self, key: object) -> bool:
        return key in self._hits

    def retry_after(self, key: str, now: datetime) -> int | None:
        q = self._hits.get(key)
        if q is None:
            return None
        while q and now - q[0] >= self.window:
            q.popleft()
        if not q:
            del self._hits[key]
            return None
        if len(q) < self.limit:
            return None
        return max(1, math.ceil((q[0] + self.window - now).total_seconds()))

    def hit(self, key: str, now: datetime) -> None:
        q = self._hits.pop(key, None) or deque()
        q.append(now)
        while len(q) > self.limit:
            q.popleft()
        self._hits[key] = q  # 移到末尾：最近使用
        while len(self._hits) > self.max_keys:
            self._hits.popitem(last=False)
