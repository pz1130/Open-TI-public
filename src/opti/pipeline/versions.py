"""按配置版本缓存处理器与富化器：快照变化后第一次取用时重建，旧的一套宽限后关闭。

重建失败时保留正在使用的一套，立刻关闭这次已打开的客户端，并把错误交给 on_status；
同一份配置在 RETRY_SECONDS 内不再重试，避免每处理一条数据都重建一次。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from opti.configs.runtime import ConfigSnapshot
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor

log = logging.getLogger("opti.app")
Closer = Callable[[], Awaitable[None]]
GRACE_SECONDS = 150.0  # 大于富化超时 120 秒：在途任务用旧富化器跑完
RETRY_SECONDS = 60.0  # 重建失败后，同一份配置隔多久再试


@dataclass(frozen=True, eq=False)
class Pipeline:
    enrichment: EnrichmentService
    processor: Processor


class PipelineBuildFailed(Exception):
    """重建中途失败。closers 是已经打开、必须立刻关掉的客户端。"""

    def __init__(self, closers: list[Closer], cause: BaseException) -> None:
        super().__init__(f"{type(cause).__name__}: {cause}")
        self.closers = list(closers)
        self.cause = cause


def _failure_text(exc: BaseException) -> str:
    cause = exc.cause if isinstance(exc, PipelineBuildFailed) else exc
    text = f"{type(cause).__name__}: {cause}".splitlines()[0].strip()
    return text or type(cause).__name__


class PipelineCache:
    def __init__(
        self,
        build: Callable[[ConfigSnapshot], tuple[Pipeline, list[Closer]]],
        *,
        grace: float = GRACE_SECONDS,
        on_status: Callable[[str | None], None] | None = None,
        retry_seconds: float = RETRY_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._build = build
        self._grace = grace
        self._on_status = on_status
        self._retry_seconds = retry_seconds
        self._clock = clock
        self._failed: tuple[str, float] | None = None  # 最近一次重建失败的配置 key 与时间
        self._key: str | None = None
        self._current: Pipeline | None = None
        self._closers: list[Closer] = []
        self._status: str | None = None
        self._retiring: dict[asyncio.Task[None], list[Closer]] = {}

    def get(self, snapshot: ConfigSnapshot) -> Pipeline:
        key = snapshot.digest(
            "rules", "organization", "vendors", "software", "connectors", "operations"
        )
        if self._current is not None and key == self._key:
            return self._current
        if (
            self._current is not None
            and self._failed is not None
            and self._failed[0] == key
            and self._clock() - self._failed[1] < self._retry_seconds
        ):
            return self._current
        try:
            pipeline, closers = self._build(snapshot)
        except Exception as exc:
            opened = exc.closers if isinstance(exc, PipelineBuildFailed) else []
            self._close_now(opened)
            message = _failure_text(exc)
            self._set_status(message)
            self._failed = (key, self._clock())
            if self._current is None:
                raise
            log.warning("富化器重建失败，继续使用上一套：%s", message, exc_info=True)
            return self._current
        if self._current is not None:
            self._retire(self._closers)
            log.info("配置已更新（规则 v%d），处理器与富化器已重建", snapshot.rules_version)
        self._key, self._current, self._closers = key, pipeline, closers
        self._failed = None
        self._set_status(None)
        return self._current

    def _set_status(self, message: str | None) -> None:
        if message == self._status:
            return
        self._status = message
        if self._on_status is not None:
            self._on_status(message)

    def _retire(self, closers: list[Closer]) -> None:
        self._schedule_close(closers, later=True)

    def _close_now(self, closers: list[Closer]) -> None:
        self._schedule_close(closers, later=False)

    def _schedule_close(self, closers: list[Closer], *, later: bool) -> None:
        if not closers:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning("没有事件循环，未能关闭富化器客户端")
            return
        task = loop.create_task(self._close_later(closers) if later else _close_all(closers))
        self._retiring[task] = closers
        task.add_done_callback(lambda t: self._retiring.pop(t, None))

    async def _close_later(self, closers: list[Closer]) -> None:
        await asyncio.sleep(self._grace)
        await _close_all(closers)

    async def close(self) -> None:
        pending = dict(self._retiring)
        for task in pending:
            task.cancel()
        for task, closers in pending.items():
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await _close_all(closers)
        await _close_all(self._closers)
        self._closers = []


async def _close_all(closers: list[Closer]) -> None:
    for close in closers:
        try:
            await close()
        except Exception:
            log.warning("关闭旧富化器失败", exc_info=True)
