"""Web 管理的配置（设计 2026-10-12-web-config-phase1）：版本、校验、历史、恢复与生效状态。"""

from __future__ import annotations

import difflib
import json
import smtplib
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy import text as sql_text
from sqlalchemy.exc import DBAPIError

from opti.alerting.config import (
    Channel,
    SmtpServer,
    webhook_secret,
)
from opti.alerting.email import EmailSink
from opti.alerting.teams import TeamsSink
from opti.alerting.views import Notice
from opti.api import config_store
from opti.api.deps import ApiDeps, CurrentUser, Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import (
    AlertingTestIn,
    AlertingTestOut,
    ConfigErrorOut,
    ConfigOut,
    ConfigProcessOut,
    ConfigRestoreIn,
    ConfigRevisionDetailOut,
    ConfigRevisionOut,
    ConfigSaveIn,
    ConfigSecretOut,
    ConfigSecretsOut,
    ConfigStatusOut,
    ConfigValidateIn,
    ConfigValidateOut,
    RematchOut,
    SharingTestIn,
    TemplatePreviewIn,
    TemplatePreviewOut,
    TicketsTestOut,
)
from opti.configs import kinds, revisions
from opti.configs import secrets as config_secrets
from opti.configs.kinds import KindName
from opti.configs.runtime import EDGE_STATUS_KEY, combine_digest
from opti.core.siem import SiemEvent
from opti.db.models import AuditLog
from opti.pipeline import kev as kev_pipeline
from opti.pipeline import retention
from opti.pipeline.retention import RetentionConfig
from opti.pipeline.tasks import recompute_campaigns, rematch_kev, rematch_leak_posts
from opti.sdk.http import HttpError, HttpPolicy, RateLimitedHttpClient
from opti.sharing import SharingConfig
from opti.siem import SyslogSender, WebhookSender, siem_problems
from opti.takedown.render import EvidenceLine, TemplateError, build_context, render_text
from opti.takedown.targets import Target
from opti.takedown.templates import template_errors, templates_from_dir
from opti.tickets.factory import build_remote_client
from opti.tickets.remote import TicketRemoteError, http_factory

router = APIRouter(tags=["config"])
_READ = {"rules": Perm.RULES_TEST}
_WRITE = {
    "rules": Perm.RULES_WRITE,
    "organization": Perm.ORGANIZATION_WRITE,
    "alerting": Perm.ALERTING_WRITE,
}
AFTER_SAVE: dict[str, Callable[[], Awaitable[Any]]] = {
    "campaigns": lambda: recompute_campaigns.kiq(),
    "vendors": lambda: rematch_leak_posts.kiq(),
    "software": lambda: rematch_kev.kiq(),
}
REMATCH_KINDS = ("vendors", "software")
SMTP_SECRETS = ("smtp_username", "smtp_password")
SIEM_SECRETS = ("siem_signing_key", "siem_webhook_token")
STALE = timedelta(minutes=10)
HIDE = timedelta(hours=24)


def read_perm(kind: str) -> Perm:
    return _READ.get(kind, Perm.CONFIG_READ)


def write_perm(kind: str) -> Perm:
    return _WRITE.get(kind, Perm.CONFIG_WRITE)


async def _reader(kind: KindName, user: CurrentUser) -> Principal:
    if read_perm(kind) not in user.perms:
        raise HTTPException(403, "forbidden")
    return user


async def _writer(kind: KindName, user: CurrentUser) -> Principal:
    if kind == "connectors":
        # 参数与法务批准分属两种权限，只能经 /connectors/{id}/config、/approval、/restore 修改
        raise HTTPException(403, {"reason": "use_connector_endpoints"})
    if write_perm(kind) not in user.perms:
        raise HTTPException(403, "forbidden")
    return user


Reader = Annotated[Principal, Depends(_reader)]
Writer = Annotated[Principal, Depends(_writer)]
StatusReader = Annotated[Principal, Depends(require(Perm.CONFIG_READ))]
AlertingAdmin = Annotated[Principal, Depends(require(Perm.ALERTING_WRITE))]
ConfigAdmin = Annotated[Principal, Depends(require(Perm.CONFIG_WRITE))]


def _invalid(e: kinds.ConfigInvalid) -> HTTPException:
    return HTTPException(422, {"errors": e.errors})


async def _current(deps: ApiDeps, kind: KindName) -> ConfigOut:
    builtin = (
        templates_from_dir(deps.settings.takedown_templates).data()
        if kind == "takedown_templates"
        else None
    )
    async with deps.sessions() as s:
        row = await revisions.latest(s, kind)
    if row is None:
        text = kinds.read_file(kind, deps.settings)
        model = kinds.parse(kind, text, allow_aliases=True)
        return ConfigOut(
            kind=kind,
            version=0,
            source="file",
            file_path=str(kinds.file_path(kind, deps.settings))
            if kinds.kind(kind).has_file
            else None,
            yaml=text,
            data=kinds.to_data(kind, model),
            digest=kinds.digest_of(text),
            builtin=builtin,
        )
    try:
        model = kinds.parse(kind, row.content)
        text = row.content
    except kinds.ConfigInvalid:
        model = deps.config.snapshot.get(kind)
        text = kinds.from_data(kind, kinds.to_data(kind, model))
    return ConfigOut(
        kind=kind,
        version=row.version,
        source="db",
        yaml=text,
        data=kinds.to_data(kind, model),
        digest=row.digest,
        created_by=row.created_by,
        created_at=row.created_at,
        note=row.note,
        restored_from=row.restored_from,
        builtin=builtin,
    )


def _text_of(kind: KindName, body: ConfigValidateIn) -> str:
    return body.yaml if body.yaml is not None else kinds.from_data(kind, body.data or {})


@router.get("/config/status")
async def config_status(request: Request, user: StatusReader) -> ConfigStatusOut:
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions() as s:
        heads = await revisions.heads(s)
        rows = await revisions.statuses(s)
        secret_stamps = {
            name: await config_secrets.stamp(s, name)
            for name in kinds.KINDS
            if kinds.kind(name).secret_names is not None
        }
    processes = [
        ConfigProcessOut(
            process=r.process,
            kind=r.kind,
            version=r.version,
            digest=r.digest,
            error=r.error,
            updated_at=r.updated_at,
            stale=now - r.updated_at > STALE,
            edge=False,
        )
        for r in rows
        if now - r.updated_at <= HIDE
    ]
    if deps.edge_store is not None:
        try:
            raw = await deps.edge_store.hgetall(EDGE_STATUS_KEY)
        except Exception:
            raw = {}
        for name, value in (raw or {}).items():
            try:
                item = json.loads(value)
                updated = datetime.fromisoformat(item["updated_at"])
            except (ValueError, KeyError, TypeError):
                continue
            if now - updated <= HIDE:
                processes.append(
                    ConfigProcessOut(
                        process=str(name),
                        kind=str(item["kind"]),
                        version=int(item["version"]),
                        digest=str(item["digest"]),
                        error=item.get("error"),
                        updated_at=updated,
                        stale=now - updated > STALE,
                        edge=True,
                    )
                )
    current: dict[str, int] = {}
    digest: dict[str, str] = {}
    for kind_name in kinds.KINDS:
        current[kind_name] = heads[kind_name].version if kind_name in heads else 0
        content_digest = (
            heads[kind_name].digest
            if kind_name in heads
            else kinds.digest_of(kinds.read_file(kind_name, deps.settings))
        )
        # 进程上报的是正文与密钥变更戳的合成值。
        digest[kind_name] = (
            combine_digest(content_digest, secret_stamps[kind_name])
            if kind_name in secret_stamps
            else content_digest
        )
    processes.sort(key=lambda p: (p.kind, p.process))
    return ConfigStatusOut(current=current, current_digest=digest, processes=processes)


@router.get("/config/{kind}/secrets")
async def config_secrets_state(kind: KindName, request: Request, user: Writer) -> ConfigSecretsOut:
    k = kinds.kind(kind)
    if k.secret_names is None:
        raise HTTPException(404, "this config has no secrets")
    deps = get_deps(request)
    async with deps.sessions() as s:
        rows = await config_secrets.states(
            s, kind, k.secret_names(deps.config.snapshot.get(kind)), fallback=k.env_fallback
        )
    return ConfigSecretsOut(
        encryption_key=deps.keyring is not None,
        secrets=[ConfigSecretOut(**asdict(row)) for row in rows],
    )


def _sanitized(exc: Exception) -> str:
    if isinstance(exc, HttpError):
        return f"HTTP {exc.status}" if exc.status is not None else "网络错误"
    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP 错误（{type(exc).__name__}）"
    if isinstance(exc, OSError):
        return f"连接失败（{type(exc).__name__}）"
    return type(exc).__name__


@router.post("/config/alerting/test")
async def test_alerting_channel(
    body: AlertingTestIn, request: Request, user: AlertingAdmin
) -> AlertingTestOut:
    deps = get_deps(request)
    now = deps.clock()
    retry = deps.alerting_tests.retry_after(str(user.user_id), now)
    if retry is not None:
        raise HTTPException(429, "test rate limit reached", headers={"Retry-After": str(retry)})
    deps.alerting_tests.hit(str(user.user_id), now)
    try:
        channel = Channel.model_validate({**body.channel, "enabled": True})
        smtp = (
            SmtpServer.model_validate(body.smtp)
            if body.smtp is not None
            else deps.config.snapshot.alerting.smtp
        )
    except ValidationError as exc:
        raise HTTPException(
            422,
            {
                "errors": [
                    {
                        "path": ".".join(str(part) for part in err["loc"]),
                        "message": str(err["msg"]),
                        "line": None,
                    }
                    for err in exc.errors()
                ]
            },
        ) from None
    stored = deps.config.snapshot.alerting_secrets
    saved_smtp = deps.config.snapshot.alerting.smtp
    # 已存的 SMTP 账号只发往已保存的服务器；草稿改了服务器就必须重新输入。
    same_smtp = (smtp.host, smtp.port, smtp.starttls) == (
        saved_smtp.host,
        saved_smtp.port,
        saved_smtp.starttls,
    )

    def secret(name: str) -> str | None:
        if body.secrets.get(name):
            return body.secrets[name]
        if name in SMTP_SECRETS and not same_smtp:
            return None
        return stored.get(name)

    notice = Notice(
        title="Open-TI 测试消息",
        facts=(
            ("渠道", channel.name),
            ("发送人", user.username),
            ("时间", now.isoformat(timespec="seconds")),
        ),
        link=deps.public_base_url,
    )
    error: str | None = None
    http = RateLimitedHttpClient(
        HttpPolicy(max_retries=0, timeout=15.0), transport=deps.alerting_transport
    )
    try:
        if channel.type == "teams":
            url = secret(webhook_secret(channel.id))
            if not url or not url.startswith("https://"):
                error = "未设置 https Webhook 地址"
            else:
                await TeamsSink(http, url, name=channel.id).send_notice(notice)
        elif not same_smtp and any(
            not body.secrets.get(name) and stored.get(name) for name in SMTP_SECRETS
        ):
            error = "SMTP 服务器已修改，已保存的用户名和密码不会发往新服务器，请重新输入后再测试"
        else:
            send = deps.smtp_sender(smtp, secret("smtp_username"), secret("smtp_password"))
            await EmailSink(channel.id, smtp, channel.recipients, send).send_notice(notice)
    except Exception as exc:  # 只返回脱敏后的原因
        error = _sanitized(exc)
    finally:
        await http.aclose()
    async with deps.sessions.begin() as s:
        await record(
            s,
            request,
            user,
            "config.alerting_tested",
            target_type="config",
            target_id="alerting",
            detail={"channel": channel.id, "type": channel.type, "ok": error is None},
        )
    return AlertingTestOut(ok=error is None, error=error)


def _test_event(deps: ApiDeps, now: datetime) -> SiemEvent:
    return SiemEvent(
        alert_id=0,
        project_id=deps.rules.project,
        severity="info",
        category="threat_intel",
        score=0,
        reasons=("test",),
        entity_type="domain",
        entity_value="test.invalid",
        title="Open-TI 测试事件",
        created_at=now,
        link=deps.public_base_url,
    )


@router.post("/config/sharing/test")
async def test_sharing(body: SharingTestIn, request: Request, user: ConfigAdmin) -> AlertingTestOut:
    deps = get_deps(request)
    now = deps.clock()
    key = f"sharing:{user.user_id}"
    retry = deps.alerting_tests.retry_after(key, now)
    if retry is not None:
        raise HTTPException(429, "test rate limit reached", headers={"Retry-After": str(retry)})
    deps.alerting_tests.hit(key, now)
    try:
        cfg = SharingConfig.model_validate(body.sharing).siem
    except ValidationError as exc:
        raise HTTPException(
            422,
            {
                "errors": [
                    {
                        "path": ".".join(map(str, err["loc"])),
                        "message": str(err["msg"]),
                        "line": None,
                    }
                    for err in exc.errors()
                ]
            },
        ) from None
    stored = deps.config.snapshot.secrets("sharing")
    # 已存的令牌与签名密钥只发往已保存的 Webhook 地址；草稿改了地址就必须重新输入。
    same_url = cfg.webhook.url == deps.config.snapshot.sharing.siem.webhook.url
    reused = {name: stored.get(name) if same_url else None for name in SIEM_SECRETS}
    signing = body.secrets.get("siem_signing_key", reused["siem_signing_key"])
    token = body.secrets.get("siem_webhook_token", reused["siem_webhook_token"])
    retype = not same_url and any(
        name not in body.secrets and stored.get(name) for name in SIEM_SECRETS
    )
    event = _test_event(deps, now)
    error: str | None = None
    http = RateLimitedHttpClient(
        HttpPolicy(max_retries=0, timeout=15.0), transport=deps.alerting_transport
    )
    try:
        if body.target == "syslog":
            if not cfg.syslog.enabled:
                error = "Syslog 未启用"
            else:
                await SyslogSender(cfg.syslog).send([event])
        elif not cfg.webhook.enabled:
            error = "Webhook 未启用"
        elif retype:
            error = "Webhook 地址已修改，已保存的令牌和签名密钥不会发往新地址，请重新输入后再测试"
        else:
            problems = siem_problems(cfg, signing_key=signing, webhook_token=token)
            if problems:
                error = problems[0]
            else:
                sender = WebhookSender(
                    http, cfg.webhook, key=signing.encode() if signing else None, token=token
                )
                payload, headers = sender.request(event)
                response = await http.post_bytes(
                    cfg.webhook.url, payload, headers=headers, timeout=cfg.webhook.timeout_seconds
                )
                if not 200 <= response.status_code < 300:
                    error = f"HTTP {response.status_code}"
    except ssl.SSLError as exc:
        error = f"TLS 握手失败（{type(exc).__name__}）"
    except Exception as exc:
        error = _sanitized(exc)
    finally:
        await http.aclose()
    async with deps.sessions.begin() as session:
        await record(
            session,
            request,
            user,
            "config.sharing_tested",
            target_type="config",
            target_id="sharing",
            detail={"target": body.target, "ok": error is None},
        )
    return AlertingTestOut(ok=error is None, error=error)


@router.post("/config/tickets/test")
async def test_tickets(request: Request, user: ConfigAdmin) -> TicketsTestOut:
    """测试已保存的 Jira / ServiceNow 配置与密钥（不接受草稿，密钥不会发往未保存的地址）。"""
    deps = get_deps(request)
    now = deps.clock()
    key = f"tickets:{user.user_id}"
    retry = deps.alerting_tests.retry_after(key, now)
    if retry is not None:
        raise HTTPException(429, "test rate limit reached", headers={"Retry-After": str(retry)})
    snapshot = deps.config.snapshot
    cfg = snapshot.tickets
    if cfg.mode not in ("jira", "servicenow"):
        raise HTTPException(400, "connection test is only available for jira and servicenow")
    deps.alerting_tests.hit(key, now)
    factory = http_factory(cfg.proxy, transport=deps.alerting_transport, max_retries=0)
    client = build_remote_client(cfg, snapshot.secrets("tickets"), factory)
    result = TicketsTestOut(ok=True)
    if client is None:
        result = TicketsTestOut(ok=False, kind="incomplete", detail="missing secret")
    else:
        try:
            await client.check()
        except TicketRemoteError as exc:
            result = TicketsTestOut(ok=False, kind=exc.kind, detail=exc.public_message())
        except Exception as exc:
            result = TicketsTestOut(ok=False, kind="unavailable", detail=_sanitized(exc))
    async with deps.sessions.begin() as session:
        await record(
            session, request, user, "config.tickets_tested", target_type="config",
            target_id="tickets", detail={"mode": cfg.mode, "ok": result.ok, "kind": result.kind},
        )  # fmt: skip
    return result


SAMPLE_HOST = "login.example-bank-secure.top"
SAMPLE_URL = f"https://{SAMPLE_HOST}/verify"


@router.post("/config/takedown_templates/preview")
async def preview_template(
    body: TemplatePreviewIn, request: Request, user: StatusReader
) -> TemplatePreviewOut:
    deps = get_deps(request)
    errors = template_errors(body.text)
    now = deps.clock()
    target = Target(
        body.kind,
        f"{body.kind}:sample",
        "示例服务商 Example Provider",
        "abuse@example.net",
        None,
        "sample",
    )
    ctx = build_context(
        deps.organization,
        target,
        language=body.language,
        host=SAMPLE_HOST,
        url=SAMPLE_URL,
        category="phishing_site",
        first_seen=now,
        evidence=[EvidenceLine("screenshot", now, "0" * 64, SAMPLE_URL)],
        ips=["203.0.113.10"],
        now=now,
    )
    if errors:
        return TemplatePreviewOut(subject="", body="", errors=errors)
    try:
        material = render_text(body.text, ctx, name=f"{body.language}/{body.kind}.txt")
    except TemplateError:
        return TemplatePreviewOut(subject="", body="", errors=errors)
    return TemplatePreviewOut(subject=material.subject, body=material.body, errors=[])


@router.get("/config/software/kev-products")
async def kev_products(
    request: Request, user: StatusReader, vendor: str = Query(min_length=1, max_length=200)
) -> list[str]:
    async with get_deps(request).sessions() as session:
        rows = await kev_pipeline.products(session, vendor)
    return list(dict.fromkeys(product for _, product, _ in rows))[:200]


@router.get("/config/{kind}/rematch")
async def rematch_status(kind: KindName, request: Request, user: Reader) -> RematchOut:
    if kind not in REMATCH_KINDS:
        raise HTTPException(404, "this config has no rematch")
    async with get_deps(request).sessions() as session:
        row = await session.scalar(
            select(AuditLog)
            .where(
                AuditLog.target_type == "config",
                AuditLog.target_id == kind,
                AuditLog.action.in_(("config.rematch_queued", "config.rematched")),
            )
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
    if row is None:
        return RematchOut(status="none")
    detail = row.detail or {}
    if row.action == "config.rematch_queued":
        return RematchOut(status="queued", version=detail.get("version"), at=row.ts)
    if "error" in detail:
        return RematchOut(
            status="failed", version=detail.get("version"), error=str(detail["error"]), at=row.ts
        )
    return RematchOut(
        status="done", version=detail.get("version"), alerts=detail.get("alerts"), at=row.ts
    )


@router.get("/config/{kind}")
async def get_config(kind: KindName, request: Request, user: Reader) -> ConfigOut:
    return await _current(get_deps(request), kind)


@router.post("/config/{kind}/validate")
async def validate_config(
    kind: KindName, body: ConfigValidateIn, user: Reader
) -> ConfigValidateOut:
    try:
        text = _text_of(kind, body)
        model = kinds.parse(kind, text)
    except kinds.ConfigInvalid as e:
        return ConfigValidateOut(ok=False, errors=[ConfigErrorOut(**x) for x in e.errors])
    return ConfigValidateOut(ok=True, yaml=text, data=kinds.to_data(kind, model))


async def _retention_preview(
    deps: ApiDeps, cfg: RetentionConfig
) -> tuple[dict[str, int] | None, bool, str | None]:
    try:
        async with deps.sessions.begin() as s:
            await s.execute(sql_text("SET LOCAL statement_timeout = '30s'"))
            now = deps.clock()
            counts = await retention.preview(s, cfg, now=now)
            return counts, await retention.exceeds_batch(s, cfg, now=now), None
    except DBAPIError as e:
        if "canceling statement due to statement timeout" in str(e.orig):
            return None, False, "timeout"
        raise


async def _check_retention(deps: ApiDeps, kind: KindName, model: Any, confirmed: bool) -> None:
    if kind != "retention" or confirmed:
        return
    assert isinstance(model, RetentionConfig)
    current = deps.config.snapshot.retention
    if any(getattr(model, f) < getattr(current, f) for f in RetentionConfig.model_fields):
        preview, capped, error = await _retention_preview(deps, model)
        raise HTTPException(
            409,
            {
                "reason": "retention_shortened",
                "preview": preview,
                "preview_capped": capped,  # 发现、案件及其告警、证据、下架只统计了下一轮
                "preview_error": error,
            },
        )


async def _after_save(request: Request, user: Principal, kind: KindName, changed: bool) -> None:
    if not changed:
        return
    if kind in REMATCH_KINDS:
        deps = get_deps(request)
        async with deps.sessions.begin() as session:
            await record(
                session,
                request,
                user,
                "config.rematch_queued",
                target_type="config",
                target_id=kind,
                detail={"kind": kind, "version": deps.config.snapshot.version(kind)},
            )
    if (hook := AFTER_SAVE.get(kind)) is not None:
        await hook()


@router.put("/config/{kind}")
async def save_config(
    kind: KindName, body: ConfigSaveIn, request: Request, user: Writer
) -> ConfigOut:
    try:
        text = _text_of(kind, body)
        model = kinds.parse(kind, text)
    except kinds.ConfigInvalid as e:
        raise _invalid(e) from None
    await _check_retention(get_deps(request), kind, model, body.confirm_retention)
    changed = await config_store.store(
        request,
        user,
        kind,
        text,
        model,
        base_version=body.base_version,
        confirm=body.confirm_project_change,
        note=body.note,
        restored_from=None,
        confirm_oidc=body.confirm_oidc_change,
        secrets=body.secrets,
    )
    await _after_save(request, user, kind, changed)
    return await _current(get_deps(request), kind)


@router.get("/config/{kind}/revisions")
async def list_revisions(kind: KindName, request: Request, user: Reader) -> list[ConfigRevisionOut]:
    async with get_deps(request).sessions() as s:
        rows = await revisions.history(s, kind)
    return [ConfigRevisionOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/config/{kind}/revisions/{version}")
async def get_revision(
    kind: KindName, version: int, request: Request, user: Reader
) -> ConfigRevisionDetailOut:
    deps = get_deps(request)
    async with deps.sessions() as s:
        row = await revisions.get(s, kind, version)
        current = await revisions.latest(s, kind)
    if row is None or current is None:
        raise HTTPException(404, "unknown revision")
    diff = "".join(
        difflib.unified_diff(
            current.content.splitlines(keepends=True),
            row.content.splitlines(keepends=True),
            fromfile=f"v{current.version}",
            tofile=f"v{row.version}",
        )
    )
    base = ConfigRevisionOut.model_validate(row, from_attributes=True)
    return ConfigRevisionDetailOut(**base.model_dump(), yaml=row.content, diff=diff)


@router.post("/config/{kind}/revisions/{version}/restore")
async def restore_revision(
    kind: KindName, version: int, body: ConfigRestoreIn, request: Request, user: Writer
) -> ConfigOut:
    deps = get_deps(request)
    async with deps.sessions() as s:
        row = await revisions.get(s, kind, version)
    if row is None:
        raise HTTPException(404, "unknown revision")
    try:
        model = kinds.parse(kind, row.content)
    except kinds.ConfigInvalid as e:
        raise _invalid(e) from None
    await _check_retention(deps, kind, model, body.confirm_retention)
    changed = await config_store.store(
        request,
        user,
        kind,
        row.content,
        model,
        base_version=body.base_version,
        confirm=body.confirm_project_change,
        note=f"恢复 v{version}",
        restored_from=version,
        confirm_oidc=body.confirm_oidc_change,
    )
    await _after_save(request, user, kind, changed)
    return await _current(deps, kind)
