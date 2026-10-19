"""研判运行时配置（设计 2026-10-10-llm-providers）：每次从数据库读取并解密，改完不用重启。

研判 worker 每轮调用 load 并新建客户端；处理器经 RuntimeCache 读取，30 秒内复用。
已启用但主用不可用（缺密钥、缺主密钥、解密失败）时按"研判已关闭"处理，排队中的请求按规则放行。
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import httpx
import yaml
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.adjudication import LlmConfig, PublicInput, build_public_input
from opti.core.config import ProjectRules
from opti.core.secretbox import Keyring, SecretError
from opti.db.models import LlmProvider, LlmSettings
from opti.llm import FailoverAdjudicator, ProviderSpec, open_adjudicator
from opti.llm_presets import BY_KEY, provider_base_url
from opti.organization import Organization

log = logging.getLogger("opti.llm")
SETTINGS_ID = 1
CACHE_SECONDS = 30.0
LEGACY_CONFIG = Path("config/llm.yaml")
FIELDS = {"api_key": "密钥", "proxy": "代理"}


def aad(provider_id: int, field: str) -> str:
    return f"llm_provider:{provider_id}:{field}"


class Unavailable(Exception):
    """供应商不可用：未知预设、缺必填密钥、缺主密钥或解密失败。消息不含密钥。"""


def spec_for(row: LlmProvider, keyring: Keyring | None) -> ProviderSpec:
    preset = BY_KEY.get(row.preset)
    if preset is None:
        raise Unavailable(f"{row.name} 使用了未知的预设 {row.preset}")

    def unseal(blob: bytes | None, field: str) -> str | None:
        if blob is None:
            return None
        if keyring is None:
            raise Unavailable(
                "尚未初始化凭据加密主密钥，请由管理员前往「配置 → 管理员 → 凭据加密主密钥」完成初始化"
            )
        try:
            return keyring.decrypt(blob, aad=aad(row.id, field))
        except SecretError as e:
            raise Unavailable(f"{row.name} 的{FIELDS[field]}无法解密：{e}") from None

    key = unseal(row.api_key_enc, "api_key")
    if preset.key_required and not key:
        raise Unavailable(f"{row.name} 缺少 API 密钥")
    return ProviderSpec(
        id=row.id, name=row.name, preset=row.preset, protocol=preset.protocol, auth=preset.auth,
        base_url=provider_base_url(row.preset, row.base_url), model=row.model, api_key=key, proxy=unseal(row.proxy_enc, "proxy"),
        json_mode=row.json_mode, temperature=row.temperature, timeout=float(row.timeout_seconds),
    )  # fmt: skip


def settings_cfg(row: LlmSettings | None) -> LlmConfig:
    if row is None:
        return LlmConfig()
    return LlmConfig(
        gray_zone=(row.gray_zone_low, row.gray_zone_high), max_per_run=row.max_per_run,
        max_attempts=row.max_attempts, max_wait_minutes=row.max_wait_minutes,
        summary_language=row.summary_language, code_enabled=row.code_enabled,
    )  # fmt: skip


@dataclass(frozen=True)
class Runtime:
    cfg: LlmConfig | None  # None：未启用或主用不可用
    primary: ProviderSpec | None = None
    backup: ProviderSpec | None = None
    problem: str | None = None


async def load(
    session: AsyncSession, keyring: Keyring | None, *, include_disabled: bool = False
) -> Runtime:
    """include_disabled：命令行在正式启用前用主用供应商做连通性检查与金标准评测。"""
    row = await session.get(LlmSettings, SETTINGS_ID)
    if row is None or not (row.enabled or include_disabled):
        return Runtime(None)
    primary_row = await session.get(LlmProvider, row.primary_id) if row.primary_id else None
    if primary_row is None:
        return Runtime(None, problem="已启用但没有主用供应商" if row.enabled else None)
    try:
        primary = spec_for(primary_row, keyring)
    except Unavailable as e:
        log.warning("大模型研判不可用，按规则放行：%s", e)
        return Runtime(None, problem=f"主用供应商不可用：{e}")
    backup: ProviderSpec | None = None
    problem: str | None = None
    backup_row = await session.get(LlmProvider, row.backup_id) if row.backup_id else None
    if backup_row is not None:
        try:
            backup = spec_for(backup_row, keyring)
        except Unavailable as e:
            log.warning("备用供应商不可用：%s", e)
            problem = f"备用供应商不可用：{e}"
    return Runtime(settings_cfg(row), primary, backup, problem)


async def report(session: AsyncSession, rt: Runtime, *, now: datetime) -> None:
    """研判 worker 每轮记录自己看到的问题，页面据此提示（API 进程看不到 worker 的主密钥）。

    没有设置行时什么也不做；不改 updated_at（那是管理员修改设置的时间）。
    """
    await session.execute(
        update(LlmSettings)
        .where(LlmSettings.id == SETTINGS_ID)
        .values(worker_checked_at=now, worker_problem=rt.problem)
    )


class RuntimeCache:
    """处理器用：TTL 内复用上次读取的结果。"""

    def __init__(
        self,
        keyring: Keyring | None,
        *,
        ttl: float = CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._keyring, self._ttl, self._clock = keyring, ttl, clock
        self._value: Runtime | None = None
        self._at = 0.0

    def set_keyring(self, keyring: Keyring) -> None:
        self._keyring = keyring
        self._value = None

    async def cfg(self, session: AsyncSession) -> LlmConfig | None:
        now = self._clock()
        if self._value is None or now - self._at >= self._ttl:
            self._value, self._at = await load(session, self._keyring), now
        return self._value.cfg


class StaticLlm:
    """固定配置（测试与命令行用）。"""

    def __init__(self, cfg: LlmConfig | None) -> None:
        self._cfg = cfg

    async def cfg(self, session: AsyncSession) -> LlmConfig | None:
        return self._cfg


@asynccontextmanager
async def adjudicator(
    rt: Runtime, *, transport: httpx.AsyncBaseTransport | None = None
) -> AsyncIterator[FailoverAdjudicator | None]:
    if rt.cfg is None or rt.primary is None:
        yield None
        return
    async with open_adjudicator(
        rt.primary, rt.backup, summary_language=rt.cfg.summary_language, transport=transport
    ) as adj:
        yield adj


def sample_input(rules: ProjectRules, organization: Organization) -> PublicInput:
    """连通性测试用的公开样例（llm-check 与页面"测试"共用）。"""
    return build_public_input(
        {
            "document": {
                "title": f"{organization.name} approves new infrastructure financing",
                "source_name": "llm-check",
            },
            "contexts": [
                f"{organization.name} said on Monday it approved new financing for infrastructure projects."
            ],
            "terms": [organization.name],
        },
        category="brand_mention",
        rules=rules,
        organization=organization.name,
        short_name=organization.short_name,
    )


async def rekey(session: AsyncSession, keyring: Keyring) -> int:
    """把旧主密钥加密的字段改用当前主密钥重新加密，返回改动的字段数。解密失败抛 SecretError。"""
    changed = 0
    rows = (await session.scalars(select(LlmProvider).with_for_update())).all()
    for row in rows:
        for field in FIELDS:
            attr = f"{field}_enc"
            blob: bytes | None = getattr(row, attr)
            if blob is None or keyring.is_current(blob):
                continue
            plain = keyring.decrypt(blob, aad=aad(row.id, field))
            setattr(row, attr, keyring.encrypt(plain, aad=aad(row.id, field)))
            changed += 1
    return changed


def warn_legacy(path: Path = LEGACY_CONFIG) -> None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
    except (OSError, yaml.YAMLError):
        return
    if isinstance(data, dict) and data.get("backend") not in (None, "none"):
        log.warning("%s 已不再生效：大模型研判改在页面「大模型研判」中配置", path)
