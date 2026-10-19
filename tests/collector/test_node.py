import asyncio
import contextlib
import json
from typing import Any

import pytest

from opti.collector.node import CollectorNode, CollectorSettings
from opti.gateway.jobs import Job


async def _fast_sleep(seconds: float) -> None:
    await asyncio.sleep(min(seconds, 0.05))


async def test_node_runs_jobs_and_streams(world: Any) -> None:
    settings = CollectorSettings(
        gateway_url="http://gw", node_id="hk1", token="unused", streams=("echo",),
        concurrency=2, lease_wait=0.2, heartbeat_interval=0.1,
        config_dir=world.paths.config_dir,
    )  # fmt: skip
    node = CollectorNode(settings, world.client, registry=world.registry, sleep=_fast_sleep)
    task = asyncio.create_task(node.run())
    try:
        job = Job.new(
            "enrich",
            {"enricher": "static", "type": "domain", "value": "sbr-loans.com"},
            ttl=30,
            reply=True,
        )
        await world.jobs.submit(job)
        result = await world.jobs.wait(job.id, timeout=5)
        assert result is not None and result["exists"] is True
        for _ in range(100):
            if len(world.enqueued) >= 2:
                break
            await asyncio.sleep(0.05)
        assert {i.source_item_id for i in world.enqueued} >= {"0", "1"}
        assert "echo" in node.status()["streams"]
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def test_settings_from_env_require_https_and_token() -> None:
    with pytest.raises(ValueError, match="OPTI_NODE_ID"):
        CollectorSettings.from_env({"OPTI_GATEWAY_URL": "https://gw:8443"})
    with pytest.raises(ValueError, match="https"):
        CollectorSettings.from_env(
            {"OPTI_GATEWAY_URL": "http://gw:8443", "OPTI_NODE_ID": "hk1",
             "OPTI_SECRET_COLLECTOR_NODE_TOKEN": "t" * 40}
        )  # fmt: skip
    s = CollectorSettings.from_env(
        {"OPTI_GATEWAY_URL": "https://gw:8443", "OPTI_NODE_ID": "hk1",
         "OPTI_SECRET_COLLECTOR_NODE_TOKEN": "t" * 40,
         "OPTI_COLLECTOR_STREAMS": "certstream, own_domain_ct"}
    )  # fmt: skip
    assert s.streams == ("certstream", "own_domain_ct") and s.node_id == "hk1"


async def test_result_reporting_survives_long_gateway_outage(world: Any) -> None:
    from opti.collector.client import GatewayError

    attempts = 0

    async def report(job_id: str, result: dict[str, Any]) -> None:
        nonlocal attempts
        attempts += 1
        if attempts <= 8:
            raise GatewayError(503, "temporarily unavailable")

    world.client.result = report
    node = CollectorNode(
        CollectorSettings(gateway_url="http://gw", node_id="hk1", token="unused"),
        world.client,
        sleep=_fast_sleep,
    )
    await node._report("job", {"status": "ok"})
    assert attempts == 9


async def test_slow_runs_do_not_starve_enrichment(world: Any) -> None:
    """长时间的采集运行占满执行槽时，境内同步等待的富化任务仍要及时得到处理。"""
    import yaml

    (world.paths.config_dir / "echo.yaml").write_text(
        yaml.safe_dump({"enabled": True, "license_approved": True,
                        "config": {"delay": 30, "items": [{"matches": [{"domain": "sbr-loans.com"}]}]}})
    )  # fmt: skip
    settings = CollectorSettings(
        gateway_url="http://gw", node_id="hk1", token="unused", concurrency=1,
        run_concurrency=1, lease_wait=0.2, heartbeat_interval=60, config_dir=world.paths.config_dir,
    )  # fmt: skip
    node = CollectorNode(settings, world.client, registry=world.registry, sleep=_fast_sleep)
    task = asyncio.create_task(node.run())
    try:
        for i in range(2):  # 两个慢运行：一个占住运行槽，另一个排队
            await world.jobs.submit(
                Job.new(
                    "run_connector", {"run_id": i, "connector_id": "echo", "cursors": {}}, ttl=120
                )
            )
        await asyncio.sleep(0.5)
        job = Job.new(
            "enrich", {"enricher": "static", "type": "domain", "value": "x.com"}, ttl=30, reply=True
        )
        await world.jobs.submit(job)
        result = await world.jobs.wait(job.id, timeout=5)
        assert result is not None and result["exists"] is True
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_status_reports_connector_readiness(
    world: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPTI_SECRET_ECHO_TOKEN", "should-not-leak")
    settings = CollectorSettings(gateway_url="http://gw", node_id="hk1", token="unused",
                                 config_dir=world.paths.config_dir)  # fmt: skip
    node = CollectorNode(settings, world.client, registry=world.registry)
    report = node.status()["connectors"]
    assert set(report) == {"echo", "static"}
    assert report["echo"]["runnable"] is True
    assert set(report["echo"]) == {"runnable", "reason", "credentials"}
    assert "should-not-leak" not in json.dumps(report)
