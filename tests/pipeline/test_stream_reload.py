import asyncio
import contextlib
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from sqlalchemy import select

from opti import organization as org_mod
from opti.configs.runtime import ConfigRuntime, ConfigSnapshot
from opti.core.config import ProjectRules
from opti.db.models import ConnectorRun
from opti.pipeline import app as app_mod
from opti.pipeline.app import build_app
from opti.sdk.registry import Registry
from opti.settings import Settings

ECHO = {
    "id": "echo", "name": "Echo", "version": "0.1.0", "category": "ct", "kind": ["poll"],
    "tier": "free", "entrypoint": "opti.sdk.testing:EchoConnector",
    "config_schema": {"type": "object", "properties": {"items": {"type": "array", "default": []}}},
}  # fmt: skip


async def test_stream_reconnects_on_rules_change(
    sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = ConfigRuntime.static(sbr_rules)
    calls: list[str] = []

    async def fake_once(app, connector_id, *, enqueue, allow_unapproved, stop):  # type: ignore[no-untyped-def]
        calls.append(app.config.snapshot.rules.project)
        if len(calls) == 1:
            await stop.wait()  # 规则更新前一直在流式采集
            return 0
        return 7  # 第二次连接：流自然结束

    monkeypatch.setattr(app_mod, "run_connector_once", fake_once)
    task = asyncio.create_task(
        app_mod.run_stream(SimpleNamespace(config=rt), "certstream", enqueue=None)  # type: ignore[arg-type]
    )
    try:
        while not calls:
            await asyncio.sleep(0)
        rt.apply(ConfigSnapshot.of(sbr_rules))  # digest 不变：不重连
        await asyncio.sleep(0)
        assert calls == [sbr_rules.project]
        rt.apply(ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "next"})))
        assert await asyncio.wait_for(task, 1) == 7
        assert calls == [sbr_rules.project, "next"]
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        org_mod.set_current(None)


@pytest.mark.db
async def test_rules_change_cancel_is_not_a_connector_failure(
    clean_db: str,
    sbr_rules: ProjectRules,
    sbr_rules_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """连接器一直阻塞、不看 stop。规则变化后超时取消，这次运行不能记成失败。"""
    root = tmp_path / "connectors"
    (root / "echo").mkdir(parents=True)
    (root / "echo" / "connector.yaml").write_text(yaml.safe_dump(ECHO))
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "echo.yaml").write_text(yaml.safe_dump({"enabled": True, "license_approved": True}))
    application = await build_app(
        Settings(
            database_url=clean_db, rules_path=sbr_rules_path, config_dir=cfg,
            state_dir=tmp_path / "state", alerting_config=tmp_path / "alerting.yaml",
        ),
        enrichers={}, sinks=[], registry=Registry([root]),
    )  # fmt: skip
    release = asyncio.Event()
    entered = asyncio.Event()

    async def hang(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        entered.set()
        await release.wait()  # 不读取 stop，安静的流在规则变化后只能靠超时取消
        if False:
            yield None

    async def enqueue(_item: object) -> None:
        return None

    monkeypatch.setattr(app_mod, "collect", hang)
    task = asyncio.create_task(
        app_mod.run_stream(application, "echo", enqueue=enqueue, stop_timeout=0.05)  # type: ignore[arg-type]
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        application.config.apply(
            ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "next"}))
        )
        finished: list[ConnectorRun] = []
        deadline = asyncio.get_running_loop().time() + 2
        while asyncio.get_running_loop().time() < deadline:
            async with application.sessions() as s:
                rows = (await s.scalars(select(ConnectorRun).order_by(ConnectorRun.id))).all()
            finished = [row for row in rows if row.ended_at is not None]
            if finished:
                break
            await asyncio.sleep(0.01)
        assert finished, "规则变化后没有写完 connector_run"
        assert finished[0].status != "error"
        assert finished[0].message != "CancelledError"
        assert finished[0].status == "ok"
    finally:
        release.set()
        if not task.done():
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError, TimeoutError):
            await asyncio.wait_for(task, 2)
        org_mod.set_current(None)
        await application.close()
