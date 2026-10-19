import asyncio
import time
import uuid
from collections.abc import AsyncIterator

import pytest
from redis.asyncio import Redis

from opti.gateway.jobs import Job, JobQueue, MemoryJobQueue, ValkeyJobQueue


@pytest.fixture(params=["memory", pytest.param("valkey", marks=pytest.mark.db)])
async def queue(request: pytest.FixtureRequest) -> AsyncIterator[JobQueue]:
    if request.param == "memory":
        q: JobQueue = MemoryJobQueue()
    else:
        url = request.getfixturevalue("valkey_url")
        q = ValkeyJobQueue(
            Redis.from_url(url, decode_responses=True), prefix=f"opti:test:{uuid.uuid4().hex}"
        )
    yield q
    await q.close()


def _enrich(value: str = "sbr-loans.com", ttl: float = 30) -> Job:
    return Job.new(
        "enrich", {"enricher": "dns", "type": "domain", "value": value}, ttl=ttl, reply=True
    )


async def test_submit_lease_complete_wait(queue: JobQueue) -> None:
    job = _enrich()
    await queue.submit(job)
    leased = await queue.lease("hk1", wait=1)
    assert leased == job
    done = await queue.complete(job.id, "hk1", {"exists": True})
    assert done == job
    assert await queue.wait(job.id, timeout=1) == {"exists": True}


async def test_lease_times_out_when_empty(queue: JobQueue) -> None:
    started = time.monotonic()
    assert await queue.lease("hk1", wait=0.3) is None
    assert time.monotonic() - started < 3


async def test_enrich_jobs_are_leased_first(queue: JobQueue) -> None:
    run = Job.new("run_connector", {"run_id": 1, "connector_id": "dnstwist"}, ttl=60)
    enrich = _enrich()
    await queue.submit(run)
    await queue.submit(enrich)
    first = await queue.lease("hk1", wait=1)
    second = await queue.lease("hk1", wait=1)
    assert first is not None and first.kind == "enrich"
    assert second is not None and second.kind == "run_connector"


async def test_expired_jobs_are_skipped(queue: JobQueue) -> None:
    """等待方已经放弃的任务不再领取，免得节点白跑。"""
    stale = Job(uuid.uuid4().hex, "enrich", {"value": "x"}, deadline=time.time() - 1, reply=True)
    await queue.submit(stale)
    assert await queue.lease("hk1", wait=0.3) is None


async def test_result_from_other_node_is_rejected(queue: JobQueue) -> None:
    job = _enrich()
    await queue.submit(job)
    await queue.lease("hk1", wait=1)
    assert await queue.complete(job.id, "sg1", {"exists": False}) is None
    assert await queue.complete(job.id, "hk1", {"exists": True}) == job


async def test_unknown_job_cannot_be_completed(queue: JobQueue) -> None:
    assert await queue.complete("nope", "hk1", {}) is None


async def test_wait_times_out(queue: JobQueue) -> None:
    job = _enrich()
    await queue.submit(job)
    assert await queue.wait(job.id, timeout=0.3) is None


async def test_run_jobs_have_no_reply(queue: JobQueue) -> None:
    """run_connector 的结果由网关直接写库，没有等待方，不应留下结果。"""
    job = Job.new("run_connector", {"run_id": 7}, ttl=60)
    await queue.submit(job)
    await queue.lease("hk1", wait=1)
    assert await queue.complete(job.id, "hk1", {"status": "ok"}) == job
    assert await queue.wait(job.id, timeout=0.3) is None


async def test_waiter_wakes_when_result_arrives(queue: JobQueue) -> None:
    job = _enrich()
    await queue.submit(job)

    async def node() -> None:
        leased = await queue.lease("hk1", wait=1)
        assert leased is not None
        await asyncio.sleep(0.1)
        await queue.complete(leased.id, "hk1", {"a": ["203.0.113.5"]})

    task = asyncio.create_task(node())
    assert await queue.wait(job.id, timeout=3) == {"a": ["203.0.113.5"]}
    await task


def test_job_round_trips_and_rejects_unknown_kind() -> None:
    job = _enrich()
    assert Job.from_dict(job.to_dict()) == job
    with pytest.raises(ValueError):
        Job.from_dict({**job.to_dict(), "kind": "shell"})


async def test_completion_retry_is_idempotent_and_keeps_owner(queue: JobQueue) -> None:
    job = _enrich()
    await queue.submit(job)
    await queue.lease("hk1", wait=1)
    assert await queue.complete(job.id, "hk1", {"exists": True}) == job
    assert await queue.complete(job.id, "hk1", {"exists": False}) == job
    assert await queue.complete(job.id, "sg1", {}) is None
    assert await queue.wait(job.id, timeout=1) == {"exists": True}


@pytest.mark.db
async def test_production_queue_can_long_poll_beyond_default_socket_timeout(
    valkey_url: str,
) -> None:
    queue = ValkeyJobQueue.from_url(valkey_url)
    try:
        assert await queue.lease("hk1", wait=5.2) is None
    finally:
        await queue.close()


async def test_lease_can_be_limited_to_kinds(queue: JobQueue) -> None:
    """采集节点为富化任务保留独立的执行槽，只领取指定类型的任务。"""
    run = Job.new("run_connector", {"run_id": 1}, ttl=60)
    await queue.submit(run)
    assert await queue.lease("hk1", wait=0.3, kinds=("enrich",)) is None
    enrich = _enrich()
    await queue.submit(enrich)
    assert await queue.lease("hk1", wait=1, kinds=("enrich",)) == enrich
    assert await queue.lease("hk1", wait=1, kinds=("run_connector",)) == run
