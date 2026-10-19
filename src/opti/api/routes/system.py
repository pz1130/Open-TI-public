"""管理员首次初始化凭据加密主密钥；密钥文件不进入数据库或配置历史。"""

from __future__ import annotations

import os
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, SecretStr
from sqlalchemy import select, text

from opti import service_control as control
from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.configs.identity import IdentityConfig
from opti.configs.secrets import aad
from opti.core.policy import OperationsConfig
from opti.core.secretbox import (
    ENV_CURRENT,
    Keyring,
    SecretError,
    generate_key,
    initialize_master_key,
    master_key_path,
)
from opti.db.models import ConfigSecret, LlmProvider

router = APIRouter(prefix="/admin", tags=["system"])
Admin = Annotated[Principal, Depends(require(Perm.CONFIG_WRITE))]


class MasterKeyStatus(BaseModel):
    configured: bool
    source: Literal["environment", "managed", "none"]
    has_encrypted_credentials: bool


class MasterKeyInitialize(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: SecretStr | None = None  # 省略时生成；恢复已有数据库时必须导入原主密钥


class MasterKeyInitialized(BaseModel):
    configured: bool = True
    backup_key: str | None = None  # 新生成的值只在这一响应返回，不写入查询缓存


async def _sealed(request: Request) -> list[tuple[bytes, str]]:
    deps = get_deps(request)
    async with deps.sessions() as s:
        fields = [
            (bytes(row.value_enc), aad(row.kind, row.name))
            for row in await s.scalars(
                select(ConfigSecret).where(ConfigSecret.value_enc.is_not(None))
            )
            if row.value_enc is not None
        ]
        for provider in await s.scalars(select(LlmProvider)):
            for field in ("api_key", "proxy"):
                blob = getattr(provider, f"{field}_enc")
                if blob is not None:
                    fields.append((bytes(blob), f"llm_provider:{provider.id}:{field}"))
        return fields


@router.get("/master-key")
async def master_key_status(request: Request, response: Response, user: Admin) -> MasterKeyStatus:
    response.headers["Cache-Control"] = "no-store"
    deps = get_deps(request)
    source: Literal["environment", "managed", "none"] = "none"
    if deps.keyring is not None:
        source = "environment" if os.environ.get(ENV_CURRENT, "").strip() else "managed"
    return MasterKeyStatus(
        configured=deps.keyring is not None,
        source=source,
        has_encrypted_credentials=bool(await _sealed(request)),
    )


@router.post("/master-key")
async def master_key_initialize(
    body: MasterKeyInitialize, request: Request, response: Response, user: Admin
) -> MasterKeyInitialized:
    response.headers["Cache-Control"] = "no-store"
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await s.execute(text("SELECT pg_advisory_xact_lock(7041100031)"))
        if deps.keyring is not None or master_key_path(deps.settings.state_dir).exists():
            raise HTTPException(409, "主密钥已配置；初始化不会覆盖已有密钥")
        # 环境变量格式有误时先修复部署参数，避免其他进程使用不同的来源。
        if os.environ.get(ENV_CURRENT, "").strip():
            raise HTTPException(409, "环境变量中的主密钥无效，请先移除无效值后重启服务")
        sealed = await _sealed(request)
        if sealed and body.key is None:
            raise HTTPException(409, "已有加密凭据，请导入原主密钥恢复，不能生成新密钥")
        raw = body.key.get_secret_value().strip() if body.key is not None else generate_key()
        ring = Keyring.from_env({ENV_CURRENT: raw})
        if ring is None:
            raise HTTPException(422, "主密钥必须是标准 Base64 编码的 32 字节")
        try:
            for blob, context in sealed:
                ring.decrypt(blob, aad=context)
        except SecretError:
            raise HTTPException(422, "该主密钥无法解密已有凭据，请导入原主密钥") from None
        try:
            ring = initialize_master_key(deps.settings.state_dir, raw)
        except FileExistsError:
            raise HTTPException(409, "主密钥已由其他请求初始化，请刷新页面") from None
        except OSError:
            raise HTTPException(503, "主密钥目录不可写，请检查平台持久化目录的挂载权限") from None
        await record(
            s,
            request,
            user,
            "system.master_key_initialized",
            detail={"imported": body.key is not None},
        )
    deps.keyring = ring
    deps.config.set_keyring(ring)
    await deps.config.refresh()
    return MasterKeyInitialized(backup_key=raw if body.key is None else None)


@router.get("/settings-schema")
async def settings_schema(user: Admin) -> dict[str, object]:
    return {
        "identity": IdentityConfig.model_json_schema(),
        "operations": OperationsConfig.model_json_schema(),
    }


@router.get("/services")
async def service_status(
    request: Request, response: Response, user: Admin
) -> control.ServiceStatus:
    response.headers["Cache-Control"] = "no-store"
    return control.status(get_deps(request).settings.service_control_dir)


@router.post("/services/restart", status_code=202)
async def restart_services(
    body: control.RestartRequest, request: Request, response: Response, user: Admin
) -> control.RestartOperation:
    response.headers["Cache-Control"] = "no-store"
    deps = get_deps(request)
    directory = deps.settings.service_control_dir
    if directory is None or not control.status(directory).available:
        raise HTTPException(503, "服务重启控制器尚未连接，请先更新平台 Docker 部署")
    try:
        with control.queue_lock(directory):
            previous = control.operation(directory)
            if previous and previous.phase in control.ACTIVE:
                raise HTTPException(409, "已有重启任务正在执行，请等待完成")
            now = deps.clock()
            job = control.RestartOperation(
                id=uuid.uuid4().hex,
                services=list(dict.fromkeys(body.services)),
                phase="queued",
                requested_at=now,
                updated_at=now,
            )
            # Commit audit before the separate controller is allowed to act.
            async with deps.sessions.begin() as session:
                await record(
                    session,
                    request,
                    user,
                    "system.services_restart_requested",
                    detail={
                        "operation_id": job.id,
                        "services": job.services,
                        "reason": body.reason,
                    },
                )
            control.atomic_json(directory / "operation.json", job)
    except control.ControlBusy:
        raise HTTPException(409, "已有重启请求正在提交，请稍后刷新") from None
    except (OSError, ValueError):
        raise HTTPException(503, "服务重启队列不可用，请检查控制器挂载目录") from None
    return job
