"""Create one local superadmin on upgrade/start, with a random one-time password."""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti.api.rbac import Role
from opti.db import audit
from opti.db.models import AppUser

BOOTSTRAP_FILE = "bootstrap-superadmin.json"


async def ensure_superadmin(
    sessions: async_sessionmaker[AsyncSession], state_dir: Path, now: datetime
) -> None:
    from opti.api.security import create_user

    async with sessions.begin() as s:
        await s.execute(select(func.pg_advisory_xact_lock(func.hashtext("opti:access_management"))))
        users = list(await s.scalars(select(AppUser)))
        # Never recreate a deliberately disabled/renamed account or change existing passwords.
        if any(Role.SUPERADMIN in (*u.roles, *u.assigned_roles) for u in users):
            return
        names = {u.username for u in users}
        username, n = "superadmin", 1
        while username in names:
            n += 1
            username = f"superadmin-{n}"
        password = secrets.token_urlsafe(24)
        account = await create_user(
            s,
            username=username,
            password=password,
            roles=[Role.SUPERADMIN],
            now=now,
            display_name="超级管理员",
        )
        account.must_change_password = True
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / BOOTSTRAP_FILE
        temporary = state_dir / ("." + BOOTSTRAP_FILE + secrets.token_hex(8))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump({"username": username, "password": password}, file)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        await audit.append(
            s,
            actor="bootstrap",
            action="user.bootstrap",
            now=now,
            target_type="app_user",
            target_id=username,
            detail={"roles": [Role.SUPERADMIN]},
        )
    logging.getLogger(__name__).warning(
        "初始超管账号 %s 已创建；随机初始密码仅保存在 %s，首次登录须修改密码。", username, path
    )


def clear_bootstrap_password(state_dir: Path, username: str) -> None:
    path = state_dir / BOOTSTRAP_FILE
    try:
        if json.loads(path.read_text(encoding="utf-8")).get("username") == username:
            path.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass
