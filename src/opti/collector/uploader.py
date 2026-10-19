"""回传缓冲：批量发送原始数据，网关不可用时退避重试（至少一次）；缓冲满时阻塞调用方形成背压。"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from opti.collector.client import GatewayError
from opti.sdk.models import RawItem, raw_item_to_dict

log = logging.getLogger("opti.collector.uploader")
Sleep = Callable[[float], Awaitable[None]]


class ItemSink(Protocol):
    async def items(self, items: list[dict[str, Any]]) -> int: ...


class ItemUploader:
    def __init__(
        self,
        sink: ItemSink,
        *,
        batch_size: int = 200,
        max_buffer: int = 10_000,
        linger: float = 1.0,
        backoff_max: float = 60.0,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._sink = sink
        self._batch_size = batch_size
        self._linger = linger
        self._backoff_max = backoff_max
        self._sleep = sleep
        self._q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(max_buffer)
        self._task: asyncio.Task[None] | None = None
        self.dropped = 0

    @property
    def buffered(self) -> int:
        return self._q.qsize()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def put(self, item: RawItem) -> None:
        await self._q.put(raw_item_to_dict(item))

    async def flush(self) -> None:
        await self._q.join()

    async def stop(self, timeout: float = 30.0) -> None:
        try:
            await asyncio.wait_for(self.flush(), timeout)
        except TimeoutError:
            log.error("停止时仍有 %d 条数据未回传", self.buffered)
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            batch = [await self._q.get()]
            deadline = loop.time() + self._linger
            while len(batch) < self._batch_size:
                timeout = deadline - loop.time()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self._q.get(), timeout))
                except TimeoutError:
                    break
            try:
                await self._deliver(batch)
            finally:
                for _ in batch:
                    self._q.task_done()

    async def _deliver(self, batch: list[dict[str, Any]]) -> None:
        # Switching projects can overlap a new manual scan with an old stream.
        # A rejected retired project's batch must not discard the new project's items.
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for item in batch:
            groups.setdefault(tuple(item.get("project_ids") or ()), []).append(item)
        if len(groups) > 1:
            for group in groups.values():
                await self._deliver(group)
            return
        attempt = 0
        while True:
            try:
                await self._sink.items(batch)
                return
            except GatewayError as e:
                if e.status == 413 and len(batch) > 1:
                    mid = len(batch) // 2
                    await self._deliver(batch[:mid])
                    await self._deliver(batch[mid:])
                    return
                if not e.retriable:
                    self.dropped += len(batch)
                    log.error("网关拒绝了 %d 条回传数据（%s），已丢弃", len(batch), e.status)
                    return
                delay = min(self._backoff_max, 2.0 ** min(attempt, 6))
                attempt += 1
                log.warning("回传失败（%s），%.0f 秒后重试", e.status or "网络错误", delay)
                await self._sleep(delay)
