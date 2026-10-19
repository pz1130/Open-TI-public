from collections.abc import Callable
from pathlib import Path
from typing import Any

from opti.collector.runner import JobRunner
from opti.collector.uploader import ItemUploader
from opti.core.config import ProjectRules
from opti.gateway.jobs import Job
from opti.sdk.context import MemoryCursorStore, ProjectCursorStore
from opti.sdk.registry import Registry
from opti.sdk.runtime import RuntimePaths
from opti.sdk.scan import KeywordScan, node_rules_for_scan


def _runner(world: Any, rules: ProjectRules) -> tuple[JobRunner, ItemUploader]:
    uploader = ItemUploader(world.client, linger=0.01)
    uploader.start()
    runner = JobRunner(
        registry=world.registry, rules=rules, paths=world.paths,
        uploader=uploader, saver=world.client.upload_evidence,
    )  # fmt: skip
    return runner, uploader


async def test_enrich_job_offloads_artifacts(world: Any, sbr_rules: ProjectRules) -> None:
    runner, uploader = _runner(world, sbr_rules)
    job = Job.new(
        "enrich",
        {"enricher": "static", "type": "domain", "value": "sbr-loans.com"},
        ttl=30,
        reply=True,
    )
    out = await runner.run(job)
    assert out["exists"] is True
    [ref] = out["artifacts"]
    assert "data_b64" not in ref and ref["node_id"] == "hk1"
    assert world.store.objects[ref["key"]].startswith(b"\x89PNG")
    await uploader.stop()
    await runner.aclose()


async def test_connector_job_uploads_items_then_reports_cursors(
    world: Any, sbr_rules: ProjectRules
) -> None:
    runner, uploader = _runner(world, sbr_rules)
    cursors = MemoryCursorStore()
    ProjectCursorStore(cursors, sbr_rules.project).set("echo", "last", "-1")
    job = Job.new(
        "run_connector",
        {"run_id": 1, "connector_id": "echo", "cursors": cursors.dump("echo")},
        ttl=60,
    )
    out = await runner.run(job)
    assert out["status"] == "ok" and out["items"] == 2 and out["message"] == ""
    for key, value in out["cursors"].items():
        cursors.set("echo", key, value)
    assert ProjectCursorStore(cursors, sbr_rules.project).get("echo", "last") == "1"
    # 报告结果之前，数据已经全部到达网关
    assert [i.source_item_id for i in world.enqueued] == ["0", "1"]
    await uploader.stop()
    await runner.aclose()


async def test_manual_scan_uses_job_rules_even_when_node_has_old_project(
    world: Any, sbr_rules: ProjectRules
) -> None:
    class Uploader:
        def __init__(self) -> None:
            self.items: list[Any] = []

        async def put(self, item: Any) -> None:
            self.items.append(item)

        async def flush(self) -> None:
            pass

    uploader = Uploader()
    runner = JobRunner(
        registry=world.registry,
        rules=sbr_rules,
        paths=world.paths,
        uploader=uploader,
        saver=world.client.upload_evidence,
    )  # type: ignore[arg-type]
    target = sbr_rules.model_copy(update={"project": "new-project"})
    scan = KeywordScan(
        project_id=target.project, rules_version=3, scope="domain", term="samplebrand"
    )
    job = Job.new(
        "run_connector",
        {
            "connector_id": "echo",
            "keyword_scan": {
                "scan": scan.model_dump(mode="json"),
                "rules": node_rules_for_scan(target),
            },
        },
        ttl=60,
    )
    out = await runner.run(job)
    assert out["status"] == "ok", out
    assert uploader.items and all(item.project_ids == (target.project,) for item in uploader.items)
    await runner.aclose()


async def test_unknown_or_blocked_jobs_return_errors(world: Any, sbr_rules: ProjectRules) -> None:
    runner, uploader = _runner(world, sbr_rules)
    bad = Job.new(
        "enrich", {"enricher": "nope", "type": "domain", "value": "x.com"}, ttl=30, reply=True
    )
    assert "blocked" in (await runner.run(bad))["error"]
    as_connector = Job.new(
        "run_connector", {"run_id": 2, "connector_id": "static", "cursors": {}}, ttl=60
    )
    out = await runner.run(as_connector)
    assert out["status"] == "error" and out["items"] == 0
    await uploader.stop()
    await runner.aclose()


async def test_domestic_enricher_is_refused(
    tmp_path: Path, world: Any, sbr_rules: ProjectRules, registry_writer: Callable[..., None]
) -> None:
    root, cfg = tmp_path / "dom", tmp_path / "domcfg"
    registry_writer(root, cfg, static_egress="domestic")
    uploader = ItemUploader(world.client, linger=0.01)
    runner = JobRunner(
        registry=Registry([root]), rules=sbr_rules, paths=RuntimePaths(config_dir=cfg),
        uploader=uploader, saver=world.client.upload_evidence,
    )  # fmt: skip
    job = Job.new(
        "enrich", {"enricher": "static", "type": "domain", "value": "x.com"}, ttl=30, reply=True
    )
    assert "blocked" in (await runner.run(job))["error"]
    await runner.aclose()
