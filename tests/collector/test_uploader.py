import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from opti.collector.client import GatewayError
from opti.collector.uploader import ItemUploader
from opti.sdk.models import RawItem


def _item(i: int) -> RawItem:
    return RawItem("dnstwist", f"d{i}.com", datetime(2026, 10, 2, tzinfo=UTC), None, {"i": i})


class FakeSink:
    def __init__(self, failures: list[int] | None = None) -> None:
        self.failures = list(failures or [])
        self.batches: list[list[dict[str, Any]]] = []
        self.gate = asyncio.Event()
        self.gate.set()

    async def items(self, items: list[dict[str, Any]]) -> int:
        await self.gate.wait()
        if self.failures:
            raise GatewayError(self.failures.pop(0), "x")
        self.batches.append(items)
        return len(items)


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


async def test_uploader_retries_until_gateway_accepts() -> None:
    sink, sleeps = FakeSink(failures=[503, 503]), Sleeps()
    up = ItemUploader(sink, linger=0.01, sleep=sleeps)
    up.start()
    for i in range(3):
        await up.put(_item(i))
    await asyncio.wait_for(up.flush(), 2)
    assert [len(b) for b in sink.batches] == [3]
    assert sleeps.calls == [1.0, 2.0]
    await up.stop()


async def test_network_errors_are_retried() -> None:
    sink = FakeSink()
    sink.failures = []
    calls = 0

    async def flaky(items: list[dict[str, Any]]) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise GatewayError(None, "ConnectError")
        return len(items)

    sink.items = flaky  # type: ignore[method-assign]
    up = ItemUploader(sink, linger=0.01, sleep=Sleeps())
    up.start()
    await up.put(_item(1))
    await asyncio.wait_for(up.flush(), 2)
    assert calls == 2 and up.dropped == 0
    await up.stop()


async def test_uploader_drops_rejected_batch() -> None:
    """403/422 重试也不会成功：记录并丢弃，不能卡住后面的数据。"""
    sink = FakeSink(failures=[403])
    up = ItemUploader(sink, linger=0.01, sleep=Sleeps())
    up.start()
    await up.put(_item(1))
    await asyncio.wait_for(up.flush(), 2)
    await up.put(_item(2))
    await asyncio.wait_for(up.flush(), 2)
    assert up.dropped == 1
    assert [[d["source_item_id"] for d in b] for b in sink.batches] == [["d2.com"]]
    await up.stop()


async def test_retired_project_cannot_discard_new_project_items() -> None:
    class SwitchingSink(FakeSink):
        async def items(self, items: list[dict[str, Any]]) -> int:
            if any(item["project_ids"] == ["retired"] for item in items):
                raise GatewayError(403, "unknown project")
            return await super().items(items)

    sink = SwitchingSink()
    up = ItemUploader(sink, linger=0.05)
    up.start()
    await up.put(replace(_item(1), project_ids=("retired",)))
    await up.put(replace(_item(2), project_ids=("active",)))
    await asyncio.wait_for(up.flush(), 2)
    assert up.dropped == 1
    assert [item["source_item_id"] for batch in sink.batches for item in batch] == ["d2.com"]
    await up.stop()


async def test_payload_too_large_splits_batch() -> None:
    sink = FakeSink(failures=[413])
    up = ItemUploader(sink, linger=0.05, sleep=Sleeps())
    up.start()
    for i in range(4):
        await up.put(_item(i))
    await asyncio.wait_for(up.flush(), 2)
    assert sorted(len(b) for b in sink.batches) == [2, 2]
    assert up.dropped == 0
    await up.stop()


async def test_full_buffer_applies_backpressure() -> None:
    sink = FakeSink()
    sink.gate.clear()
    up = ItemUploader(sink, linger=0.01, max_buffer=2, batch_size=1, sleep=Sleeps())
    up.start()
    for i in range(3):  # 一条在发送中，两条在缓冲里
        await up.put(_item(i))
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(up.put(_item(9)), 0.2)
    sink.gate.set()
    await asyncio.wait_for(up.flush(), 2)
    await up.stop()
