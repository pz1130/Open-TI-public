"""采集网关任务队列（设计文档 3.4）：境内提交任务，采集节点经网关长轮询领取，结果按任务 ID 回传。

两种实现：MemoryJobQueue（测试与单进程）、ValkeyJobQueue（生产，worker 与网关是不同进程）。
节点在领取后崩溃时任务会丢失：富化等待方超时，连接器运行由 sweep_stale_runs 标记失败。
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Literal, Protocol, cast

from redis.asyncio import Redis

JobKind = Literal["enrich", "run_connector"]
KINDS: tuple[JobKind, ...] = ("enrich", "run_connector")  # 领取顺序即优先级：富化有人在同步等待
RESULT_TTL = 600
Clock = Callable[[], float]


@dataclass(frozen=True)
class Job:
    id: str
    kind: JobKind
    payload: dict[str, Any]
    deadline: float  # Unix 时间；过期的任务不再领取
    reply: bool = False  # 是否有等待方（enrich 为 True；run_connector 的结果由网关直接写库）

    @classmethod
    def new(
        cls,
        kind: JobKind,
        payload: dict[str, Any],
        *,
        ttl: float,
        reply: bool = False,
        now: float | None = None,
    ) -> Job:
        start = time.time() if now is None else now
        return cls(uuid.uuid4().hex, kind, payload, start + ttl, reply)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Job:
        kind = d.get("kind")
        if kind not in KINDS:
            raise ValueError(f"未知任务类型：{kind}")
        return cls(
            id=str(d["id"]),
            kind=cast(JobKind, kind),
            payload=dict(d.get("payload") or {}),
            deadline=float(d["deadline"]),
            reply=bool(d.get("reply", False)),
        )


class JobQueue(Protocol):
    async def submit(self, job: Job) -> None: ...

    async def lease(
        self, node_id: str, wait: float, kinds: Sequence[JobKind] = KINDS
    ) -> Job | None:
        """只领取 kinds 中的任务类型（按 KINDS 的顺序作为优先级）。"""
        ...

    async def leased(self, job_id: str, node_id: str) -> Job | None: ...

    async def complete(self, job_id: str, node_id: str, result: dict[str, Any]) -> Job | None:
        """记录结果；任务不存在或不是该节点领取的返回 None。"""
        ...

    async def wait(self, job_id: str, timeout: float) -> dict[str, Any] | None: ...

    async def close(self) -> None: ...


class MemoryJobQueue:
    def __init__(self, clock: Clock = time.time) -> None:
        self._clock = clock
        self._queues: dict[JobKind, deque[Job]] = {k: deque() for k in KINDS}
        self._ready = asyncio.Condition()
        self._leases: dict[str, tuple[str, Job]] = {}
        self._results: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._completed: dict[str, float] = {}

    async def submit(self, job: Job) -> None:
        if job.reply:
            self._results[job.id] = asyncio.get_running_loop().create_future()
        async with self._ready:
            self._queues[job.kind].append(job)
            self._ready.notify_all()

    def _pop(self, kinds: Sequence[JobKind]) -> Job | None:
        for kind in KINDS:
            if kind not in kinds:
                continue
            q = self._queues[kind]
            while q:
                job = q.popleft()
                if job.deadline > self._clock():
                    return job
        return None

    async def lease(
        self, node_id: str, wait: float, kinds: Sequence[JobKind] = KINDS
    ) -> Job | None:
        async with self._ready:
            job = self._pop(kinds)
            if job is None:
                try:
                    await asyncio.wait_for(
                        self._ready.wait_for(lambda: any(self._queues[k] for k in kinds)), wait
                    )
                except TimeoutError:
                    return None
                job = self._pop(kinds)
        if job is not None:
            self._leases[job.id] = (node_id, job)
        return job

    async def leased(self, job_id: str, node_id: str) -> Job | None:
        for jid, (_, job) in list(self._leases.items()):
            expires = self._completed.get(jid, job.deadline + RESULT_TTL)
            if expires <= self._clock():
                self._leases.pop(jid, None)
                self._completed.pop(jid, None)
        lease = self._leases.get(job_id)
        return lease[1] if lease is not None and lease[0] == node_id else None

    async def complete(self, job_id: str, node_id: str, result: dict[str, Any]) -> Job | None:
        job = await self.leased(job_id, node_id)
        if job is None:
            return None
        if job_id not in self._completed:
            self._completed[job_id] = self._clock() + RESULT_TTL
            fut = self._results.get(job_id)
            if fut is not None and not fut.done():
                fut.set_result(dict(result))
        return job

    async def wait(self, job_id: str, timeout: float) -> dict[str, Any] | None:
        fut = self._results.get(job_id)
        if fut is None:
            return None
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout)
        except TimeoutError:
            return None
        finally:
            self._results.pop(job_id, None)  # 等待方放弃后迟到的结果直接丢弃

    async def close(self) -> None:
        return None


class ValkeyJobQueue:
    def __init__(self, redis: Redis, *, prefix: str = "opti:gw", clock: Clock = time.time) -> None:
        self._r = redis
        self._p = prefix
        self._clock = clock

    @classmethod
    def from_url(cls, url: str) -> ValkeyJobQueue:
        return cls(Redis.from_url(url, decode_responses=True, socket_timeout=None))

    def _queue(self, kind: JobKind) -> str:
        return f"{self._p}:jobs:{kind}"

    def _lease_key(self, job_id: str) -> str:
        return f"{self._p}:lease:{job_id}"

    def _result_key(self, job_id: str) -> str:
        return f"{self._p}:result:{job_id}"

    async def submit(self, job: Job) -> None:
        await self._r.lpush(self._queue(job.kind), json.dumps(job.to_dict()))

    async def lease(
        self, node_id: str, wait: float, kinds: Sequence[JobKind] = KINDS
    ) -> Job | None:
        keys = [self._queue(k) for k in KINDS if k in kinds]
        deadline = self._clock() + wait
        while True:
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None
            got = await self._r.brpop(keys, timeout=remaining)
            if got is None:
                return None
            job = Job.from_dict(json.loads(got[1]))
            if job.deadline <= self._clock():
                continue
            ttl = max(1, int(job.deadline - self._clock()) + RESULT_TTL)
            lease = json.dumps({"node": node_id, "job": job.to_dict()})
            await self._r.set(self._lease_key(job.id), lease, ex=ttl)
            return job

    async def leased(self, job_id: str, node_id: str) -> Job | None:
        raw = await self._r.get(self._lease_key(job_id))
        if raw is None:
            return None
        lease = json.loads(raw)
        return Job.from_dict(lease["job"]) if lease.get("node") == node_id else None

    async def complete(self, job_id: str, node_id: str, result: dict[str, Any]) -> Job | None:
        # Keep the receipt for retries; publish a reply once, atomically with completion.
        script = """
        local raw = redis.call('GET', KEYS[1])
        if not raw then return nil end
        local lease = cjson.decode(raw)
        if lease.node ~= ARGV[1] then return nil end
        if redis.call('SET', KEYS[3], '1', 'EX', ARGV[3], 'NX') then
            redis.call('EXPIRE', KEYS[1], ARGV[3])
            if lease.job.reply then
                redis.call('LPUSH', KEYS[2], ARGV[2])
                redis.call('EXPIRE', KEYS[2], ARGV[3])
            end
        end
        return raw
        """
        raw = await self._r.eval(
            script,
            3,
            self._lease_key(job_id),
            self._result_key(job_id),
            f"{self._p}:completed:{job_id}",
            node_id,
            json.dumps(result),
            RESULT_TTL,
        )
        return Job.from_dict(json.loads(raw)["job"]) if raw is not None else None

    async def wait(self, job_id: str, timeout: float) -> dict[str, Any] | None:
        got = await self._r.brpop([self._result_key(job_id)], timeout=timeout)
        if got is None:
            return None
        data = json.loads(got[1])
        return data if isinstance(data, dict) else None

    async def close(self) -> None:
        await self._r.aclose()
