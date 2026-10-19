"""定时调度：内置任务用标签定义；连接器按 manifest 的 schedule.default 自动生成（只包含合规闸门放行的）。"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncEngine
from taskiq import ScheduledTask, ScheduleSource, TaskiqScheduler

import opti.pipeline.tasks  # noqa: F401  注册任务及其 schedule 标签
from opti.configs.runtime import ConfigRuntime, process_name
from opti.core import policy
from opti.db.engine import make_engine, make_sessionmaker
from opti.pipeline.broker import broker
from opti.sdk.context import EnvSecretProvider, SecretProvider
from opti.sdk.manifest import ManifestError
from opti.sdk.registry import Registry, gate, load_instance_config
from opti.sdk.runtime import RuntimePaths
from opti.settings import Settings

log = logging.getLogger("opti.schedule")
SCHEDULABLE_KINDS = frozenset({"poll", "batch", "generator"})


class ManifestScheduleSource(ScheduleSource):
    def __init__(
        self,
        registry: Registry,
        paths: RuntimePaths,
        secrets: SecretProvider | None = None,
        *,
        settings: Settings | None = None,
    ) -> None:
        self._registry = registry
        self._paths = paths
        self._secrets = secrets or EnvSecretProvider()
        self._settings = settings
        self._engine: AsyncEngine | None = None
        self.config: ConfigRuntime | None = None

    async def startup(self) -> None:
        """有数据库时启动配置运行时：网页上启用或停用连接器，在下一次取定时任务（每分钟）时生效。"""
        if self._settings is None or not self._settings.database_url:
            return
        self._engine = make_engine(self._settings.database_url)
        self.config = await ConfigRuntime.start(
            self._settings, make_sessionmaker(self._engine), process=process_name("scheduler")
        )
        self.config.start_background()

    async def shutdown(self) -> None:
        if self.config is not None:
            await self.config.stop()
            self.config = None
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    async def get_schedules(self) -> list[ScheduledTask]:
        out: list[ScheduledTask] = []
        for m in self._registry.manifests():
            if not (set(m.kind) & SCHEDULABLE_KINDS):
                continue
            try:
                instance = load_instance_config(self._paths.config_dir, m.id)
            except ManifestError as e:
                log.warning("连接器 %s 的实例配置不合法，已跳过定时调度：%s", m.id, e)
                continue
            if not gate(m, instance, self._secrets).runnable:
                continue
            cron = instance.schedule or m.schedule.default
            if not cron:
                continue
            out.append(
                ScheduledTask(
                    task_name="opti.run_connector",
                    labels={},
                    args=[m.id],
                    kwargs={},
                    cron=cron,
                    schedule_id=f"connector:{m.id}",
                )
            )
        return out


class BuiltinScheduleSource(ScheduleSource):
    def __init__(self, manifest: ManifestScheduleSource) -> None:
        self._manifest = manifest

    async def get_schedules(self) -> list[ScheduledTask]:
        # 复用调度进程的运行时；固定 ID，不再同时注册标签来源的默认任务。
        config = self._manifest.config
        schedules = config.snapshot.operations.schedules if config else policy.TASK_CRONS
        return [
            ScheduledTask(
                task_name=f"opti.{name}",
                labels={},
                args=[],
                kwargs={},
                cron=cron,
                schedule_id=f"builtin:{name}",
            )
            for name, cron in schedules.items()
        ]


_settings = Settings.from_env()
_manifest_source = ManifestScheduleSource(
    Registry(),
    RuntimePaths(config_dir=_settings.config_dir, state_dir=_settings.state_dir),
    settings=_settings,
)
scheduler = TaskiqScheduler(
    broker,
    sources=[
        _manifest_source,
        BuiltinScheduleSource(_manifest_source),
    ],
)
