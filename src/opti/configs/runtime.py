"""各进程的配置运行时：按 digest 刷新不可变快照、上报生效状态、把规则发布给边缘服务。

工作单元（一次入库、一次请求、一次连接器运行）开始时取一次 snapshot，整个单元内只用这一份。
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Protocol, cast

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti import organization as org_mod
from opti.alerting.config import AlertingConfig
from opti.configs import kinds, revisions
from opti.configs import secrets as config_secrets
from opti.configs.connectors import ConnectorOverrides, nested
from opti.configs.identity import IdentityConfig
from opti.core import policy
from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.core.kev import SoftwareList
from opti.core.secretbox import Keyring
from opti.core.text_match import TextMatcher
from opti.core.vendors import VendorList
from opti.organization import Organization
from opti.pipeline.campaigns import CampaignConfig
from opti.pipeline.retention import RetentionConfig
from opti.sdk import config_store
from opti.sdk.models import utcnow
from opti.settings import Settings
from opti.sharing import SharingConfig
from opti.takedown.config import TakedownConfig
from opti.takedown.templates import TakedownTemplates
from opti.tickets.config import TicketsConfig

log = logging.getLogger("opti.config")
REFRESH_SECONDS = 10.0
HEARTBEAT_SECONDS = 300.0
EDGE_RULES_KEY = "opti:config:rules"
EDGE_STATUS_KEY = "opti:config:edge-status"
_DB_ERRORS = (SQLAlchemyError, OSError)

Subscriber = Callable[["ConfigSnapshot", "ConfigSnapshot"], None]


class KeyValue(Protocol):
    # redis.asyncio 的命令是普通方法、返回 Awaitable，不是 async def。
    def get(self, name: str) -> Awaitable[Any]: ...
    def set(self, name: str, value: str) -> Awaitable[Any]: ...
    def hset(self, name: str, key: str, value: str) -> Awaitable[Any]: ...
    def hgetall(self, name: str) -> Awaitable[Any]: ...


class RulePublisher(Protocol):
    def publish_if_newer(self, name: str, version: int, body: str) -> Awaitable[bool]: ...


_PUBLISH_IF_NEWER = """
local previous = redis.call('GET', KEYS[1])
if previous then
  local ok, decoded = pcall(cjson.decode, previous)
  if ok and type(decoded) == 'table' and tonumber(decoded.version)
     and tonumber(decoded.version) > tonumber(ARGV[1]) then
    return 0
  end
end
redis.call('SET', KEYS[1], ARGV[2])
return 1
"""


class RedisRulePublisher:
    """原子比较版本后发布，避免暂时离线的 API 把边缘规则降级。"""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def publish_if_newer(self, name: str, version: int, body: str) -> bool:
        return bool(await self._client.eval(_PUBLISH_IF_NEWER, 1, name, version, body))


def process_name(role: str) -> str:
    return f"{role}@{socket.gethostname()}"


def _json_digest(data: Any) -> str:
    return kinds.digest_of(json.dumps(data, sort_keys=True, ensure_ascii=False, default=str))


def combine_digest(content_digest: str, secret_stamp: str) -> str:
    return kinds.digest_of(f"{content_digest}:{secret_stamp}")


@dataclass(frozen=True, eq=False)
class KindState:
    model: Any
    version: int
    digest: str
    secrets: Mapping[str, str | None] = field(default_factory=dict)


@dataclass(frozen=True, eq=False)
class ConfigSnapshot:
    states: Mapping[str, KindState]

    @classmethod
    def of(
        cls,
        rules: ProjectRules,
        organization: Organization | None = None,
        *,
        alerting: AlertingConfig | None = None,
        alerting_secrets: Mapping[str, str | None] | None = None,
        rules_version: int = 0,
        organization_version: int = 0,
        **models: Any,
    ) -> ConfigSnapshot:
        given: dict[str, Any] = {
            "rules": rules,
            "organization": organization,
            "alerting": alerting,
            **models,
        }
        versions = {"rules": rules_version, "organization": organization_version}
        states: dict[str, KindState] = {}
        for name in kinds.KINDS:
            model = given.get(name)
            if model is None:
                model = kinds.default(name)
            secrets = dict(alerting_secrets or {}) if name == "alerting" else {}
            states[name] = KindState(
                model, versions.get(name, 0), _json_digest(kinds.to_data(name, model)), secrets
            )
        return cls(states)

    def get(self, kind: str) -> Any:
        return self.states[kind].model

    def version(self, kind: str) -> int:
        return self.states[kind].version

    def secrets(self, kind: str) -> Mapping[str, str | None]:
        return self.states[kind].secrets

    def digest(self, *kinds_: str) -> str:
        if len(kinds_) == 1:
            return self.states[kinds_[0]].digest
        return kinds.digest_of(":".join(self.states[name].digest for name in kinds_))

    def with_state(self, kind: str, state: KindState) -> ConfigSnapshot:
        return ConfigSnapshot({**self.states, kind: state})

    @property
    def rules(self) -> ProjectRules:
        return cast(ProjectRules, self.get("rules"))

    @property
    def organization(self) -> Organization:
        return cast(Organization, self.get("organization"))

    @property
    def alerting(self) -> AlertingConfig:
        return cast(AlertingConfig, self.get("alerting"))

    @property
    def retention(self) -> RetentionConfig:
        return cast(RetentionConfig, self.get("retention"))

    @property
    def campaigns(self) -> CampaignConfig:
        return cast(CampaignConfig, self.get("campaigns"))

    @property
    def takedown(self) -> TakedownConfig:
        return cast(TakedownConfig, self.get("takedown"))

    @property
    def takedown_templates(self) -> TakedownTemplates:
        return cast(TakedownTemplates, self.get("takedown_templates"))

    @property
    def tickets(self) -> TicketsConfig:
        return cast(TicketsConfig, self.get("tickets"))

    @property
    def vendors(self) -> VendorList:
        return cast(VendorList, self.get("vendors"))

    @property
    def software(self) -> SoftwareList:
        return cast(SoftwareList, self.get("software"))

    @property
    def sharing(self) -> SharingConfig:
        return cast(SharingConfig, self.get("sharing"))

    @property
    def connectors(self) -> ConnectorOverrides:
        return cast(ConnectorOverrides, self.get("connectors"))

    @property
    def identity(self) -> IdentityConfig:
        return cast(IdentityConfig, self.get("identity"))

    @property
    def operations(self) -> policy.OperationsConfig:
        return cast(policy.OperationsConfig, self.get("operations"))

    @property
    def rules_version(self) -> int:
        return self.version("rules")

    @property
    def rules_digest(self) -> str:
        return self.digest("rules")

    @property
    def organization_version(self) -> int:
        return self.version("organization")

    @property
    def organization_digest(self) -> str:
        return self.digest("organization")

    @property
    def alerting_version(self) -> int:
        return self.version("alerting")

    @property
    def alerting_digest(self) -> str:
        return self.digest("alerting")

    @property
    def alerting_secrets(self) -> Mapping[str, str | None]:
        return self.secrets("alerting")

    @cached_property
    def domain_matcher(self) -> DomainMatcher:
        return DomainMatcher(self.rules.domains)

    @cached_property
    def text_matcher(self) -> TextMatcher:
        return TextMatcher(self.rules)


def install(snapshot: ConfigSnapshot) -> None:
    """把快照中的进程级设置装进模块：当前机构、连接器网页覆盖与其凭据。"""
    org_mod.set_current(snapshot.organization)
    policy.install(snapshot.operations)
    config_store.set_current(
        {cid: inst.model_dump() for cid, inst in snapshot.connectors.connectors.items()},
        nested(dict(snapshot.secrets("connectors"))),
    )


def _file_state(kind: str, text: str) -> KindState:
    return KindState(kinds.parse(kind, text, allow_aliases=True), 0, kinds.digest_of(text))


async def _newest_valid(s: AsyncSession, kind: str) -> tuple[KindState | None, str | None]:
    error: str | None = None
    for row in await revisions.history(s, kind):
        try:
            return KindState(kinds.parse(kind, row.content), row.version, row.digest), error
        except kinds.ConfigInvalid as e:
            log.error("配置 %s v%d 无法加载：%s", kind, row.version, e)
            error = error or f"v{row.version}: {e}"
    return None, error


async def _with_secrets(
    session: AsyncSession, name: str, state: KindState, keyring: Keyring | None
) -> tuple[KindState, str | None]:
    spec = kinds.kind(name)
    if spec.secret_names is None:
        return state, None
    resolved = await config_secrets.resolve(
        session,
        name,
        spec.secret_names(state.model),
        keyring,
        fallback=spec.env_fallback,
        stored_only=spec.stored_only,
    )
    stamp = await config_secrets.stamp(session, name)
    problem = _join(
        *resolved.problems.values(),
        *(spec.problems(state.model, resolved.values) if spec.problems else []),
    )
    return KindState(
        state.model, state.version, combine_digest(state.digest, stamp), resolved.values
    ), problem


def _env_secrets(name: str, state: KindState) -> KindState:
    spec = kinds.kind(name)
    if spec.secret_names is None:
        return state
    if spec.stored_only:  # 数据库不可用：快照里没有库中密钥，读取方直接用环境变量
        return KindState(state.model, state.version, combine_digest(state.digest, "-"), {})
    resolved = config_secrets.resolve_env(
        spec.secret_names(state.model), fallback=spec.env_fallback
    )
    return KindState(state.model, state.version, combine_digest(state.digest, "-"), resolved.values)


def _join(*parts: str | None) -> str | None:
    return "；".join(part for part in parts if part) or None


class ConfigRuntime:
    def __init__(
        self,
        snapshot: ConfigSnapshot,
        *,
        sessions: async_sessionmaker[AsyncSession] | None = None,
        process: str | None = None,
        publisher: RulePublisher | None = None,
        clock: Callable[[], Any] = utcnow,
        keyring: Keyring | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._snapshot = snapshot
        self._sessions = sessions
        self._process = process
        self._publisher = publisher
        self._clock = clock
        self._keyring = keyring
        self._settings = settings
        self._file_text: dict[str, str] = {}
        self._subscribers: list[Subscriber] = []
        self._errors: dict[str, str | None] = {k: None for k in kinds.KINDS}
        self._rejected: dict[str, str] = {}
        self._reported: float | None = None
        self._published: float | None = None
        self._pipeline_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._status_tasks: set[asyncio.Task[None]] = set()
        self._refresh_lock = asyncio.Lock()

    @classmethod
    def static(
        cls,
        rules: ProjectRules,
        organization: Organization | None = None,
        *,
        alerting: AlertingConfig | None = None,
        alerting_secrets: Mapping[str, str | None] | None = None,
        sessions: async_sessionmaker[AsyncSession] | None = None,
        keyring: Keyring | None = None,
        **models: Any,
    ) -> ConfigRuntime:
        """测试与无数据库场景：固定快照；给了 sessions 时 refresh 仍会读库。"""
        return cls(
            ConfigSnapshot.of(
                rules,
                organization,
                alerting=alerting,
                alerting_secrets=alerting_secrets,
                **models,
            ),
            sessions=sessions,
            keyring=keyring,
        )

    @classmethod
    async def start(
        cls,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        *,
        process: str | None = None,
        publisher: RulePublisher | None = None,
        clock: Callable[[], Any] = utcnow,
        keyring: Keyring | None = None,
    ) -> ConfigRuntime:
        keyring = keyring if keyring is not None else Keyring.from_env(state_dir=settings.state_dir)
        file_text: dict[str, str] = {name: kinds.read_file(name, settings) for name in kinds.KINDS}
        states: dict[str, KindState] = {}
        errors: dict[str, str | None] = {k: None for k in kinds.KINDS}
        try:
            async with sessions() as s:
                for name in kinds.KINDS:
                    found, errors[name] = await _newest_valid(s, name)
                    state = found or _file_state(name, file_text[name])
                    states[name], problem = await _with_secrets(s, name, state, keyring)
                    errors[name] = _join(errors[name], problem)
        except _DB_ERRORS as e:
            log.warning("启动时读取配置失败，先用文件：%s", type(e).__name__)
            states = {
                name: _env_secrets(name, _file_state(name, file_text[name])) for name in kinds.KINDS
            }
            errors = {name: None for name in kinds.KINDS}
        rt = cls(
            ConfigSnapshot(states),
            sessions=sessions,
            process=process,
            publisher=publisher,
            clock=clock,
            keyring=keyring,
            settings=settings,
        )
        rt._errors = errors
        rt._file_text = file_text
        install(rt.snapshot)
        await rt._report(force=True)
        async with rt._refresh_lock:
            await rt._publish()
        return rt

    @property
    def snapshot(self) -> ConfigSnapshot:
        return self._snapshot

    @property
    def keyring(self) -> Keyring | None:
        return self._keyring

    @property
    def settings(self) -> Settings | None:
        return self._settings

    def set_keyring(self, keyring: Keyring) -> None:
        self._keyring = keyring
        # 密文没有变化，但此前无法解密的快照必须重新读取。
        self._keyring_changed = True

    @property
    def errors(self) -> dict[str, str | None]:
        return dict(self._errors)

    def subscribe(self, callback: Subscriber) -> Callable[[], None]:
        self._subscribers.append(callback)
        return lambda: self._subscribers.remove(callback) if callback in self._subscribers else None

    def apply(self, snapshot: ConfigSnapshot) -> None:
        """替换快照并通知订阅者（refresh 内部与测试使用）。"""
        old, self._snapshot = self._snapshot, snapshot
        install(snapshot)
        for callback in list(self._subscribers):
            try:
                callback(old, snapshot)
            except Exception:
                log.exception("配置订阅回调失败")

    async def refresh(self) -> bool:
        # 读 head、安装快照和发布（含心跳）都在这把锁里完成。
        # 正在飞的 SET 不能晚于更新的快照写完；SET 失败不算已发布，下一轮循环会重试。
        async with self._refresh_lock:
            rules_changed = False
            try:
                if self._sessions is None:
                    return False
                if self._keyring is None and self._settings is not None:
                    ring = Keyring.from_env(state_dir=self._settings.state_dir)
                    if ring is not None:
                        self.set_keyring(ring)
                keyring_changed = getattr(self, "_keyring_changed", False)
                changed: dict[str, KindState] = {}
                errors_before = dict(self._errors)
                try:
                    async with self._sessions() as s:
                        heads = await revisions.heads(s)
                        for name in kinds.KINDS:
                            spec = kinds.kind(name)
                            head = heads.get(name)
                            # 没有版本时只有带密钥的 kind 需要看密钥变更；没有来源文件的 kind 不依赖 settings
                            if head is None and (
                                spec.secret_names is None
                                or (self._settings is None and spec.has_file)
                            ):
                                continue
                            file_text = self._file_text.get(name, "")
                            content_digest = (
                                head.digest if head is not None else kinds.digest_of(file_text)
                            )
                            target = (
                                combine_digest(content_digest, await config_secrets.stamp(s, name))
                                if spec.secret_names is not None
                                else content_digest
                            )
                            if target in (
                                self._snapshot.digest(name),
                                self._rejected.get(name),
                            ) and not (keyring_changed and spec.secret_names is not None):
                                continue
                            if head is not None:
                                row = await revisions.get(s, name, head.version)
                                if row is None:
                                    continue
                                text, version = row.content, row.version
                            else:
                                text, version = file_text, 0
                            try:
                                model = kinds.parse(name, text, allow_aliases=version == 0)
                            except kinds.ConfigInvalid as e:
                                log.error(
                                    "配置 %s v%d 无法加载，保留当前版本：%s", name, version, e
                                )
                                self._rejected[name] = target
                                self._errors[name] = f"v{version}: {e}"
                                continue
                            values: Mapping[str, str | None] = {}
                            problem: str | None = None
                            if spec.secret_names is not None:
                                resolved = await config_secrets.resolve(
                                    s,
                                    name,
                                    spec.secret_names(model),
                                    self._keyring,
                                    fallback=spec.env_fallback,
                                    stored_only=spec.stored_only,
                                )
                                values = resolved.values
                                problem = _join(
                                    *resolved.problems.values(),
                                    *(spec.problems(model, values) if spec.problems else []),
                                )
                            changed[name] = KindState(model, version, target, values)
                            self._errors[name] = problem
                except _DB_ERRORS as e:
                    log.warning("刷新配置失败，保留当前快照：%s", type(e).__name__)
                    return False
                if changed:
                    self.apply(ConfigSnapshot({**self._snapshot.states, **changed}))
                    rules_changed = "rules" in changed
                self._keyring_changed = False
                await self._report(force=bool(changed) or errors_before != self._errors)
                return bool(changed)
            finally:
                await self._publish_due(rules_changed=rules_changed)

    async def _report(self, *, force: bool) -> None:
        if self._process is None or self._sessions is None:
            return
        now = time.monotonic()
        if not force and self._reported is not None and now - self._reported < HEARTBEAT_SECONDS:
            return
        snap = self._snapshot
        try:
            async with self._sessions.begin() as s:
                for kind in kinds.KINDS:
                    await revisions.report_status(
                        s, process=self._process, kind=kind,
                        version=snap.version(kind), digest=snap.digest(kind),
                        error=self._status_error(kind), now=self._clock(),
                    )  # fmt: skip
            self._reported = now
        except _DB_ERRORS as e:
            log.warning("上报配置状态失败：%s", type(e).__name__)

    def _status_error(self, kind: str) -> str | None:
        # 加载失败优先。富化器重建失败时两条状态都带同一段错误，且不含配置正文。
        return self._errors[kind] or self._pipeline_error

    def schedule_pipeline_status(self, message: str | None) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self.note_pipeline_failure(message))
        self._status_tasks.add(task)
        task.add_done_callback(self._status_tasks.discard)

    async def note_pipeline_failure(self, message: str | None) -> None:
        async with self._refresh_lock:
            if message == self._pipeline_error:
                return
            self._pipeline_error = message
            await self._report(force=True)

    async def _publish_due(self, *, rules_changed: bool) -> None:
        if self._publisher is None:
            return
        due = self._published is None or time.monotonic() - self._published >= HEARTBEAT_SECONDS
        if rules_changed or due:
            await self._publish()

    async def _publish(self) -> None:
        if self._publisher is None:
            return
        snap = self._snapshot
        body = json.dumps(
            {
                "version": snap.rules_version,
                "digest": snap.rules_digest,
                "rules": snap.rules.model_dump(mode="json"),
            },
            ensure_ascii=False,
        )
        try:
            published = await self._publisher.publish_if_newer(
                EDGE_RULES_KEY, snap.rules_version, body
            )
        except Exception:
            self._published = None
            log.warning("规则未能发布到任务队列", exc_info=True)
            return
        if not published:
            log.info("已有更新的规则版本，跳过发布 v%d", snap.rules_version)
        # 调用方持有锁。若等待 SET 期间快照已换新，刚写完的是旧正文，接着写当前这份。
        if self._snapshot is not snap:
            await self._publish()
            return
        self._published = time.monotonic()

    async def run(self, interval: float = REFRESH_SECONDS) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await self.refresh()
            except Exception:
                log.exception("配置刷新失败")

    def start_background(self, interval: float = REFRESH_SECONDS) -> None:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self.run(interval))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        pending = [task for task in self._status_tasks if not task.done()]
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def load_current(settings: Settings) -> ConfigSnapshot:
    """一次性命令：有数据库时读当前版本，否则读文件。"""
    if not settings.database_url:
        snapshot = ConfigSnapshot(
            {
                name: _env_secrets(name, _file_state(name, kinds.read_file(name, settings)))
                for name in kinds.KINDS
            }
        )
        install(snapshot)
        return snapshot
    from opti.db.engine import make_engine, make_sessionmaker

    engine = make_engine(settings.database_url)
    try:
        return (await ConfigRuntime.start(settings, make_sessionmaker(engine))).snapshot
    finally:
        await engine.dispose()
