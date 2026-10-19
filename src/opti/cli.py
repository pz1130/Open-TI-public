"""命令行：规则测试沙盒、连接器管理、手动采集与富化。"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import re
import signal
import sys
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti.api import security, tokens
from opti.api.app import openapi_schema
from opti.api.deps import ApiDeps
from opti.api.server import serve_api
from opti.collector.node import CollectorNode, CollectorSettings
from opti.configs import connector_import
from opti.configs import secrets as config_secrets
from opti.configs.runtime import ConfigRuntime, load_current, process_name
from opti.core.adjudication import AdjudicationError
from opti.core.code_evaluation import evaluate_code_llm, load_code_cases
from opti.core.config import ConfigError, ProjectRules, load_project_rules
from opti.core.domain_match import DomainMatcher
from opti.core.evaluation import (
    TextEvaluation,
    evaluate_texts,
    evaluate_texts_llm,
    load_text_cases,
    run_golden,
)
from opti.core.kev import load_software
from opti.core.report import domain_report as _domain_result
from opti.core.report import score_dict as _score_dict
from opti.core.scoring import Severity, score_domain
from opti.core.secret_guard import install_log_filter
from opti.core.secretbox import Keyring, SecretError, generate_key
from opti.core.secrets import fingerprint as secret_fingerprint
from opti.core.secrets import require_mask_key
from opti.core.siem import SiemEvent
from opti.core.stix import build_bundle
from opti.core.text_match import TextMatcher
from opti.core.vendors import PartyMatcher, load_vendors
from opti.core.visual import MAX_REFERENCE_BYTES, dhash_bytes, hash_usable
from opti.core.watcher import compare, parse_export
from opti.db import audit
from opti.db.engine import make_engine, make_sessionmaker
from opti.db.migrate import upgrade
from opti.db.models import Alert, AppUser, Finding
from opti.db.models import CollectorNode as CollectorNodeRow
from opti.db.partitions import drop_raw_item_partitions_before
from opti.enrichers.signals import build_domain_signals
from opti.enrichers.tranco.enricher import TrancoIndex, refresh
from opti.export import stix as stix_export
from opti.gateway.dispatch import dispatch_connector_run
from opti.gateway.pki import make_dev_pki
from opti.gateway.server import serve
from opti.intake.snippet import canary_snippets
from opti.organization import current_organization
from opti.pipeline import (
    acceptance,
    connectors,
    dsar,
    evidence,
    kev,
    llm_runtime,
    metrics,
    retention,
    watcher,
)
from opti.pipeline.app import build_app, run_connector_once, run_stream, set_app
from opti.pipeline.broker import broker
from opti.pipeline.reports import month_period
from opti.pipeline.tasks import (
    capture_evidence,
    daily_report,
    dispatch_pending,
    ingest,
    monthly_report,
    recheck_watchlist,
    recompute_campaigns,
    rematch_kev,
    rematch_leak_posts,
    weekly_report,
)
from opti.sandbox.favicon import MAX_ICON_BYTES, favicon_fingerprint
from opti.sdk.base import BaseConnector, Enricher, MissingCredential
from opti.sdk.context import EnvSecretProvider
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.manifest import ManifestError, validate_instance_config
from opti.sdk.models import RawItem, raw_item_to_dict
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, gate, load_instance_config
from opti.sdk.runtime import ConnectorBlocked, RuntimePaths, collect, create
from opti.settings import Settings
from opti.siem import build_senders

SCORING_ENRICHERS = ("dns", "rdap", "tranco")


def _cmd_connectors(registry: Registry, paths: RuntimePaths) -> int:
    secrets = EnvSecretProvider()
    for m in registry.manifests():
        g = gate(m, load_instance_config(paths.config_dir, m.id), secrets)
        row = {
            "id": m.id,
            "tier": m.tier.value,
            "kind": list(m.kind),
            "egress": m.egress,
            "commercial_use": m.commercial_use,
            "runnable": g.runnable,
            "reason": g.reason,
        }
        print(json.dumps(row, ensure_ascii=False))
    return 0


async def _cmd_collect(
    args: argparse.Namespace, rules: ProjectRules, registry: Registry, paths: RuntimePaths
) -> int:
    conn = create(
        registry, args.connector, rules, paths=paths, allow_unapproved=args.allow_unapproved
    )
    if not isinstance(conn, BaseConnector):
        print(f"错误：{args.connector} 是富化器，请使用 enrich 子命令", file=sys.stderr)
        await conn.ctx.http().aclose()
        return 2
    enrichers: list[Enricher] = []
    if args.enrich:
        for eid in SCORING_ENRICHERS:
            try:
                e = create(
                    registry, eid, rules, paths=paths, allow_unapproved=args.allow_unapproved
                )
            except ConnectorBlocked:
                continue
            if isinstance(e, Enricher):
                enrichers.append(e)
    matcher = DomainMatcher(rules.domains)
    try:
        plan = build_query_plan(rules)
        async for item in collect(conn, plan, max_items=args.max_items, seconds=args.seconds):
            scores: list[dict[str, Any]] = []
            for md in item.payload.get("matches", []):
                m = matcher.match(str(md.get("domain", "")))
                if m is None or m.status != "match":
                    continue
                enrichment = {e.id: await e.enrich("domain", m.domain) for e in enrichers}
                s = score_domain(build_domain_signals(m, enrichment))
                scores.append({"domain": m.domain, **_score_dict(s), "enrichment": enrichment})
            row = {
                "item_id": item.item_id,
                "connector_id": item.connector_id,
                "source_item_id": item.source_item_id,
                "fetched_at": item.fetched_at.isoformat(),
                "payload": item.payload,
                "scores": scores,
            }
            print(json.dumps(row, ensure_ascii=False, default=str), flush=True)
    finally:
        await conn.ctx.http().aclose()
        for e in enrichers:
            await e.ctx.http().aclose()
    return 0


async def _cmd_enrich(
    args: argparse.Namespace, rules: ProjectRules, registry: Registry, paths: RuntimePaths
) -> int:
    e = create(registry, args.enricher, rules, paths=paths, allow_unapproved=args.allow_unapproved)
    try:
        if not isinstance(e, Enricher):
            print(f"错误：{args.enricher} 不是富化器", file=sys.stderr)
            return 2
        out = await e.enrich(args.type, args.value)
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
        return 0
    finally:
        await e.ctx.http().aclose()


async def _cmd_tranco_refresh(registry: Registry, paths: RuntimePaths) -> int:
    instance = load_instance_config(paths.config_dir, "tranco")
    config = validate_instance_config(registry.manifest("tranco"), instance.config)
    index = TrancoIndex(Path(str(config["db_path"])))
    async with RateLimitedHttpClient() as http:
        n = await refresh(http, index)
    print(f"Tranco 列表已更新：{n} 个域名")
    return 0


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="opti", description="Open-TI 命令行工具")
    p.add_argument("--rules", type=Path, default=None, help="关键词配置文件（默认取 OPTI_RULES）")
    p.add_argument("--config-dir", type=Path, default=None)
    p.add_argument("--state-dir", type=Path, default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("match-domain", help="判断域名是否在仿冒受保护品牌，并给出评分")
    d.add_argument("domains", nargs="+")
    sub.add_parser("match-text", help="对标准输入中的文本做关键词匹配")
    et = sub.add_parser("eval-texts", help="评测文本缩写歧义误报率与召回率")
    et.add_argument("--file", type=Path, default=Path("eval/golden/texts.csv"))
    et.add_argument("--llm", action="store_true", help="同时评测规则 + 大模型")
    ec = sub.add_parser(
        "eval-code", help="用主用大模型评测代码仓库密钥研判（真假、仓库关系、注入样例）"
    )
    ec.add_argument("--file", type=Path, default=Path("eval/golden/code_secrets.csv"))
    ga = sub.add_parser("eval", help="运行全部金标准集（域名、URL、文本），每个切片交付时执行")
    ga.add_argument("--dir", type=Path, default=Path("eval/golden"))
    sub.add_parser("llm-check", help="用公开样例检查大模型配置")
    sub.add_parser("encryption-key-gen", help="生成凭据加密主密钥（也可在管理员 Web 设置中初始化）")
    sub.add_parser("rekey", help="主密钥轮换后，把已保存的密钥改用新主密钥重新加密")
    lh = sub.add_parser("logo-hash", help="从本地机构 Logo 图片生成 dHash（仅供人工复核）")
    lh.add_argument("image", type=Path)
    fh = sub.add_parser("favicon-hash", help="从本地机构站点图标生成 mmh3（仅供人工关联）")
    fh.add_argument("image", type=Path)
    sub.add_parser("siem-test", help="向已启用的 SIEM 渠道发送一条测试事件")
    vt = sub.add_parser("vendors-test", help="测试受害者名称或域名是否匹配本机构或供应商")
    vt.add_argument("victim")
    vt.add_argument("--domain", default=None)
    vr = sub.add_parser("vendors-rematch", help="重新比对近期泄露站帖子")
    vr.add_argument("--days", type=int, default=365)
    sub.add_parser("software-check", help="校验软件清单（config/software.yaml）")
    kp = sub.add_parser("kev-products", help="列出 KEV 中的厂商与产品名")
    kp.add_argument("--vendor", default=None)
    sub.add_parser("kev-rematch", help="把 KEV 条目与当前软件清单重新比对")
    sub.add_parser("campaign-recompute", help="重算仿冒活动候选（设计文档 8）")
    sub.add_parser("connectors", help="列出连接器及其合规状态")
    xs = sub.add_parser("export-stix", help="导出 STIX 2.1 Bundle")
    xs.add_argument("--days", type=int, default=30)
    xs.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default=None)
    xs.add_argument("--out", type=Path, default=None)

    c = sub.add_parser("collect", help="运行一个连接器并输出结果（JSON Lines）")
    c.add_argument("connector")
    c.add_argument("--max-items", type=int, default=None)
    c.add_argument("--seconds", type=float, default=None)
    c.add_argument("--enrich", action="store_true", help="对命中域名做 DNS/RDAP/Tranco 富化后评分")
    c.add_argument("--allow-unapproved", action="store_true", help="开发调试：绕过法务许可检查")

    e = sub.add_parser("enrich", help="运行一个富化器")
    e.add_argument("enricher")
    e.add_argument("value")
    e.add_argument("--type", default="domain")
    e.add_argument("--allow-unapproved", action="store_true")

    sub.add_parser("tranco-refresh", help="下载最新 Tranco 排名列表到本地索引")
    sub.add_parser("db-upgrade", help="把数据库迁移到最新版本")
    r = sub.add_parser("run", help="运行一次连接器，结果进入处理流水线")
    r.add_argument("connector")
    r.add_argument("--max-items", type=int, default=None)
    r.add_argument("--seconds", type=float, default=None)
    r.add_argument("--allow-unapproved", action="store_true")
    st = sub.add_parser("stream", help="常驻运行流式连接器（如 certstream），结果进入处理流水线")
    st.add_argument("connector")
    st.add_argument("--allow-unapproved", action="store_true")
    w = sub.add_parser("watchlist-recheck", help="复查到期的监视域名")
    w.add_argument("--limit", type=int, default=100)
    sub.add_parser("alerts-dispatch", help="按渠道设置推送待发送的告警")
    sub.add_parser("report-daily", help="生成并推送日报")
    sub.add_parser("report-weekly", help="生成并推送周报")
    rm = sub.add_parser("report-monthly", help="生成并推送月报（默认上一个自然月，可补生成）")
    rm.add_argument("--month", help="YYYY-MM，按报告时区计算；必须是已结束的月份")
    sub.add_parser("gateway", help="启动采集网关（mTLS，供境外采集节点连接）")
    sub.add_parser("collector", help="启动境外采集节点")
    sb = sub.add_parser("sandbox", help="启动截图沙箱服务")
    sb.add_argument("--host", default="0.0.0.0")
    sb.add_argument("--port", type=int, default=8000)
    sb.add_argument("--allow-private", action="store_true", help="允许访问内网地址（仅供测试）")
    pk = sub.add_parser("pki-dev", help="生成开发用 CA、网关证书与采集节点证书")
    pk.add_argument("--out", type=Path, required=True)
    pk.add_argument("--server", action="append", required=True, help="网关证书的主机名/IP，可重复")
    pk.add_argument("--node", action="append", required=True, help="采集节点 ID，可重复")
    sub.add_parser("collectors", help="列出采集节点与最后心跳时间")
    ec = sub.add_parser("evidence-capture", help="为待取证的告警截图存证")
    ec.add_argument("--alert-id", type=int, default=None)
    ec.add_argument("--limit", type=int, default=20)
    ev = sub.add_parser("evidence-verify", help="下载证据并核对 SHA-256")
    ev.add_argument("evidence_id", type=int)
    rt = sub.add_parser("retention", help="按 config/retention.yaml 清理到期数据")
    rt.add_argument("--dry-run", action="store_true", help="只统计将删除的数量，不做任何修改")
    ds = sub.add_parser("dsar", help="数据主体请求：按邮箱或姓名检索个人信息，确认后删除或匿名化")
    who = ds.add_mutually_exclusive_group(required=True)
    who.add_argument("--email")
    who.add_argument("--name")
    ds.add_argument(
        "--erase", action="store_true", help="删除或匿名化检索到的数据（需同时带 --confirm）"
    )
    ds.add_argument("--confirm", action="store_true")
    wc = sub.add_parser("watcher-compare", help="与 Watcher 导出的域名清单对照，互相检查漏报")
    wc.add_argument("file", type=Path)
    wc.add_argument("--days", type=int, default=30)
    ac = sub.add_parser("acceptance", help="生成 MVP 验收报告（Markdown + JSON）")
    ac.add_argument("--days", type=int, default=30)
    ac.add_argument("--watcher", type=Path, default=None, help="Watcher 导出的域名清单")
    ac.add_argument("--golden", type=Path, default=Path("eval/golden"))
    ac.add_argument("--out", type=Path, default=Path("acceptance"))
    sub.add_parser("api", help="启动研判接口与前端")
    ua = sub.add_parser("user-add", help="新建本地账号（口令取 OPTI_NEW_PASSWORD 或交互输入）")
    ua.add_argument("username")
    ua.add_argument("--role", action="append", required=True, help="角色，可重复")
    ua.add_argument("--display-name", default="")
    up = sub.add_parser("user-passwd", help="重设口令并注销该用户全部会话")
    up.add_argument("username")
    sub.add_parser("user-list", help="列出账号来源、状态与角色（不显示口令或令牌）")
    ud = sub.add_parser("user-disable", help="停用账号并注销全部会话")
    ud.add_argument("username")
    tc = sub.add_parser("token-create", help="签发 API Token（令牌只显示一次）")
    tc.add_argument("name")
    tc.add_argument(
        "--scope", action="append", required=True, help="作用域，可重复，如 blocklist:export"
    )
    tc.add_argument("--days", type=int, default=365)
    sub.add_parser("token-list", help="列出 API Token（不显示令牌本身）")
    tr = sub.add_parser("token-revoke", help="吊销 API Token")
    tr.add_argument("name")
    sub.add_parser("audit-verify", help="校验审计日志哈希链")
    sub.add_parser("secret-match", help="从标准输入核对候选密钥是否出现在记录中")
    sub.add_parser("api-schema", help="输出研判接口的 OpenAPI（供前端生成类型）")
    sub.add_parser("intake", help="启动对外入口（金丝雀与公众举报）")
    sub.add_parser("syslog", help="接收官网访问日志 Referer")
    cs = sub.add_parser("canary-snippet", help="生成官网金丝雀代码片段")
    cs.add_argument("--base-url", required=True)
    return p


DB_COMMANDS = frozenset(
    {
        "db-upgrade",
        "run",
        "stream",
        "watchlist-recheck",
        "alerts-dispatch",
        "vendors-rematch",
        "kev-products",
        "kev-rematch",
        "campaign-recompute",
        "report-daily",
        "report-weekly",
        "report-monthly",
        "export-stix",
        "collectors",
        "evidence-capture",
        "evidence-verify",
        "retention",
        "dsar",
        "watcher-compare",
        "acceptance",
    }
)


SERVICE_COMMANDS = frozenset(
    {
        "gateway",
        "collector",
        "sandbox",
        "pki-dev",
        "api",
        "api-schema",
        "intake",
        "syslog",
        "canary-snippet",
    }
)


def _settings(args: argparse.Namespace) -> Settings:
    env = Settings.from_env()
    return replace(
        env,
        rules_path=args.rules or env.rules_path,
        config_dir=args.config_dir or env.config_dir,
        state_dir=args.state_dir or env.state_dir,
    )


async def _enqueue(item: RawItem) -> None:
    await ingest.kiq(raw_item_to_dict(item))


async def _db_command(args: argparse.Namespace, settings: Settings) -> int:
    assert settings.database_url is not None
    if args.cmd == "stream" and settings.collector_mode == "remote":
        print(
            "错误：remote 模式下流式连接器由境外采集节点运行（在节点上设置 OPTI_COLLECTOR_STREAMS）",
            file=sys.stderr,
        )
        return 2
    if args.cmd == "db-upgrade":
        await upgrade(settings.database_url)
        print("数据库已迁移到最新版本")
        engine = make_engine(settings.database_url)
        try:
            sessions = make_sessionmaker(engine)
            async with sessions() as s:
                filled = await metrics.backfill_samples(s)
            imported = await connector_import.import_legacy(
                sessions, settings.state_dir, Keyring.from_env(), datetime.now(UTC)
            )
        except connector_import.ImportFailed as e:
            print(f"错误：导入连接器网页设置失败：{e}", file=sys.stderr)
            return 2
        finally:
            await engine.dispose()
        if filled:
            print(f"已补算 {filled} 个已告警发现的 MTTD 样本")
        if imported is not None:
            print(
                f"已导入 {imported.connectors} 个连接器的网页设置与 {len(imported.secrets)} 个凭据"
                f"（原文件已改名为 {connector_import.FILE_NAME}.migrated）"
            )
        return 0
    process = process_name(f"stream-{args.connector}") if args.cmd == "stream" else None
    app = await build_app(settings, process=process)
    set_app(app)
    await broker.startup()
    if args.cmd == "stream":
        app.config.start_background()
    try:
        if (
            args.cmd == "run"
            and app.jobs is not None
            and app.registry.manifest(args.connector).egress == "overseas"
        ):
            async with app.sessions() as s, s.begin():
                run_id = await dispatch_connector_run(
                    s, app.jobs, args.connector, now=datetime.now(UTC),
                    max_items=args.max_items, seconds=args.seconds,
                )  # fmt: skip
            if run_id is None:
                print(f"{args.connector}：上一次运行尚未结束，本次未下发")
            else:
                print(f"{args.connector}：已下发到采集节点，run_id={run_id}")
        elif args.cmd == "stream":
            n = await run_stream(
                app, args.connector, enqueue=_enqueue, allow_unapproved=args.allow_unapproved
            )
            print(f"{args.connector}：已处理 {n} 条")
        elif args.cmd == "run":
            n = await run_connector_once(
                app, args.connector, enqueue=_enqueue,
                max_items=args.max_items, seconds=args.seconds, allow_unapproved=args.allow_unapproved,
            )  # fmt: skip
            print(f"{args.connector}：已处理 {n} 条")
        elif args.cmd == "watchlist-recheck":
            print(f"已复查 {await recheck_watchlist(args.limit)} 个域名")
        elif args.cmd == "vendors-rematch":
            print(f"重新比对完成，新增 {await rematch_leak_posts(args.days)} 条告警")
        elif args.cmd == "kev-products":
            async with app.sessions() as s:
                for vendor, product, n in await kev.products(s, args.vendor):
                    print(f"{vendor}\t{product}\t{n}")
        elif args.cmd == "kev-rematch":
            print(f"重新比对完成，新增 {await rematch_kev()} 条告警")
        elif args.cmd == "campaign-recompute":
            r = await recompute_campaigns()
            print(
                f"候选活动 {r['candidates']} 个（新建 {r['created']}，删除 {r['removed']}），"
                f"已确认活动新增待确认成员 {r['pending']} 个"
            )
        elif args.cmd == "export-stix":
            if not 1 <= args.days <= 3650:
                print("错误：--days 必须在 1–3650 之间", file=sys.stderr)
                return 2
            now = datetime.now(UTC)
            level = (
                Severity(args.min_severity) if args.min_severity else app.sharing.stix.min_severity
            )
            async with app.sessions() as s, s.begin():
                findings = await stix_export.collect(
                    s, app.rules, since=now - timedelta(days=args.days), min_severity=level
                )
                bundle = build_bundle(
                    findings,
                    project=app.rules.project,
                    organization=app.organization.name,
                    base_url=app.alerting.public_base_url,
                    tlp=app.sharing.stix.tlp,
                )
                await audit.append(
                    s,
                    actor="cli",
                    action="export.stix",
                    now=now,
                    detail={
                        "days": args.days,
                        "min_severity": level.value,
                        "findings": len(findings),
                        "objects": len(bundle["objects"]),
                    },
                )
            text = json.dumps(bundle, ensure_ascii=False, indent=2)
            if args.out is None:
                print(text)
            else:
                args.out.write_text(text, encoding="utf-8")
                print(
                    f"已导出 {len(findings)} 个发现、{len(bundle['objects'])} 个 STIX 对象：{args.out}"
                )
        elif args.cmd == "retention":
            now = datetime.now(UTC)
            cutoff = (now - timedelta(days=app.retention.raw_items_days)).date()
            async with app.engine.begin() as conn:
                partitions = await drop_raw_item_partitions_before(
                    conn, cutoff, dry_run=args.dry_run
                )
                async with AsyncSession(bind=conn) as s:
                    result = await retention.apply(s, app.retention, now=now)
                    if not args.dry_run:
                        await audit.append(
                            s, actor="cli", action="retention.purge", now=now,
                            detail={**result.counts, "partitions": len(partitions)},
                        )  # fmt: skip
                    await s.flush()
                if args.dry_run:
                    await conn.rollback()  # 分区与行删除同一事务，试运行统一回滚
            files = (
                len(result.objects)
                if args.dry_run
                else await retention.delete_objects(app.store, result.objects)
            )
            summary = {
                "dry_run": args.dry_run,
                "partitions": partitions,
                **result.counts,
                "evidence_files": files,
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        elif args.cmd == "dsar":
            try:
                subj = dsar.subject(email=args.email, name=args.name)
            except dsar.DsarError as e:
                print(f"错误：{e}", file=sys.stderr)
                return 2
            if args.erase and not args.confirm:
                print("错误：删除或匿名化需要同时带 --confirm", file=sys.stderr)
                return 2
            now = datetime.now(UTC)
            async with app.sessions() as s, s.begin():
                hits = await dsar.search(s, subj)
                counts = await dsar.erase(s, subj) if args.erase else hits.counts()
                await audit.append(
                    s, actor="cli", action="dsar.erase" if args.erase else "dsar.search", now=now,
                    target_type="data_subject", target_id=subj.digest, detail={"kind": subj.kind, **counts},
                )  # fmt: skip
            out: dict[str, Any] = {"subject_sha256": subj.digest, "kind": subj.kind, "erased": args.erase,
                                   "counts": counts}  # fmt: skip
            if not args.erase:
                out["samples"] = hits.samples()
            print(json.dumps(out, ensure_ascii=False, indent=2))
        elif args.cmd == "watcher-compare":
            theirs = parse_export(args.file.read_text(encoding="utf-8", errors="replace"))
            now = datetime.now(UTC)
            async with app.sessions() as s:
                ours = await watcher.our_hosts(
                    s, app.rules.project, since=now - timedelta(days=args.days), until=now
                )
                elsewhere = await watcher.known_hosts(s, app.rules.project, theirs)
            comparison = compare(ours, theirs, rules=app.rules, elsewhere=elsewhere)
            report = {"window_days": args.days, "watcher_total": len(theirs), "ours_total": len(ours),
                      **comparison.to_dict()}  # fmt: skip
            print(json.dumps(report, ensure_ascii=False, indent=2))
        elif args.cmd == "acceptance":
            now = datetime.now(UTC)
            golden = run_golden(app.rules, args.golden)
            comparison = None
            async with app.sessions() as s:
                catalog = await connectors.catalog(
                    s, app.registry, app.settings.config_dir, EnvSecretProvider(),
                    remote=app.settings.collector_mode == "remote", now=now,
                )  # fmt: skip
                if args.watcher is not None:
                    theirs = parse_export(
                        args.watcher.read_text(encoding="utf-8", errors="replace")
                    )
                    ours = await watcher.our_hosts(
                        s, app.rules.project, since=now - timedelta(days=args.days), until=now
                    )
                    elsewhere = await watcher.known_hosts(s, app.rules.project, theirs)
                    comparison = compare(ours, theirs, rules=app.rules, elsewhere=elsewhere)
                checks = await acceptance.run(
                    s, rules=app.rules, catalog=catalog, golden=golden, watcher=comparison, now=now,
                    days=args.days,
                )  # fmt: skip
            meta = {"project": app.rules.project, "now": now, "days": args.days}
            md = acceptance.render_markdown(checks, **meta)
            args.out.mkdir(parents=True, exist_ok=True)
            stem = args.out / f"acceptance-{now:%Y%m%d}"
            stem.with_suffix(".md").write_text(md, encoding="utf-8")
            stem.with_suffix(".json").write_text(
                json.dumps(acceptance.to_json(checks, **meta), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(md)
            return 1 if any(c.status == "fail" for c in checks) else 0
        elif args.cmd == "alerts-dispatch":
            print(f"已推送 {await dispatch_pending()} 条告警")
        elif args.cmd == "collectors":
            async with app.sessions() as s:
                nodes = (
                    await s.scalars(select(CollectorNodeRow).order_by(CollectorNodeRow.node_id))
                ).all()
            now = datetime.now(UTC)
            if not nodes:
                print("还没有采集节点上报心跳")
            for node in nodes:
                age = int((now - node.last_seen).total_seconds())
                streams = ", ".join(
                    f"{k}={v}" for k, v in (node.status.get("streams") or {}).items()
                )
                print(
                    f"{node.node_id}\tv{node.version}\t{age} 秒前\t缓冲 {node.status.get('buffered_items', 0)}\t{streams}"
                )
        elif args.cmd == "evidence-capture":
            if args.alert_id is not None:
                async with app.sessions() as s, s.begin():
                    await s.execute(
                        update(Alert)
                        .where(Alert.id == args.alert_id)
                        .values(evidence_status="pending", evidence_attempts=0)
                    )
            print(f"已取证 {await capture_evidence(args.limit)} 个告警")
        elif args.cmd == "evidence-verify":
            if app.store is None:
                print("错误：未配置对象存储（OPTI_S3_ENDPOINT）", file=sys.stderr)
                return 2
            async with app.sessions() as s:
                ok = await evidence.verify(s, app.store, args.evidence_id)
            print("哈希一致" if ok else "哈希不一致：证据可能被篡改")
            return 0 if ok else 1
        else:
            if args.cmd == "report-monthly":
                try:
                    month_period(datetime.now(UTC), app.alerting.report_timezone, args.month)
                except ValueError as exc:
                    print(f"错误：{exc}", file=sys.stderr)
                    return 2
                report_id = await monthly_report(args.month)
            else:
                report_id = await (daily_report if args.cmd == "report-daily" else weekly_report)()
            print(f"报告已生成：{app.alerting.public_base_url.rstrip('/')}/reports/{report_id}")
        return 0
    finally:
        await broker.shutdown()
        set_app(None)
        await app.close()


USER_COMMANDS = frozenset(
    {
        "token-create",
        "token-list",
        "token-revoke",
        "user-list",
        "user-add",
        "user-passwd",
        "user-disable",
        "audit-verify",
        "secret-match",
    }
)


def _read_password() -> str:
    env = os.environ.get("OPTI_NEW_PASSWORD")
    if env:
        return env
    first = getpass.getpass("新口令：")
    if first != getpass.getpass("再输入一次："):
        raise security.UserError("两次输入的口令不一致")
    return first


async def _user_command(args: argparse.Namespace, settings: Settings) -> int:
    assert settings.database_url is not None
    engine = make_engine(settings.database_url)
    actor = f"cli:{getpass.getuser()}"
    now = datetime.now(UTC)
    try:
        async with make_sessionmaker(engine).begin() as s:
            if args.cmd == "audit-verify":
                broken = await audit.verify_chain(s)
                if broken is None:
                    print("审计日志哈希链完整")
                    return 0
                print(f"审计日志从第 {broken} 条记录开始不一致，可能被篡改", file=sys.stderr)
                return 1
            if args.cmd == "secret-match":
                value = sys.stdin.readline().rstrip("\r\n")
                if not value:
                    print("错误：请从标准输入提供候选值", file=sys.stderr)
                    return 2
                digest = secret_fingerprint(value)  # 与采集节点相同的 HMAC
                del value
                rows = (
                    await s.scalars(
                        select(Finding.match).where(
                            Finding.match["scan"]["secrets"].contains([{"fingerprint": digest}])
                        )
                    )
                ).all()
                hits = [
                    {"repo": match.get("repo"), "file": secret.get("file"),
                     "line": secret.get("line"), "rule": secret.get("rule"), "url": secret.get("url")}
                    for match in rows
                    for secret in (match.get("scan") or {}).get("secrets") or []
                    if secret.get("fingerprint") == digest
                ]  # fmt: skip
                await audit.append(
                    s,
                    actor=actor,
                    action="secret.match",
                    now=now,
                    detail={"fingerprint_prefix": digest[:12], "matches": len(hits)},
                )
                for hit in hits:
                    print(json.dumps(hit, ensure_ascii=False))
                return 0 if hits else 1
            if args.cmd == "token-list":
                for t in await tokens.list_tokens(s):
                    print(json.dumps({
                        "name": t.name, "prefix": t.prefix, "scopes": list(t.scopes),
                        "created_by": t.created_by, "expires_at": t.expires_at.isoformat(),
                        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
                        "revoked": t.revoked_at is not None,
                    }, ensure_ascii=False))  # fmt: skip
                return 0
            if args.cmd == "token-create":
                row, token = await tokens.create_token(
                    s, name=args.name, scopes=args.scope, days=args.days, actor=actor, now=now
                )
                await audit.append(
                    s, actor=actor, action="token.create", now=now, target_type="api_token",
                    target_id=row.name, detail={"scopes": list(row.scopes), "expires_at": row.expires_at.isoformat()},
                )  # fmt: skip
                print(token)
                print(
                    f"已签发 {row.name}（到期 {row.expires_at:%Y-%m-%d}）。令牌只显示这一次，请立即保存。",
                    file=sys.stderr,
                )
                return 0
            if args.cmd == "token-revoke":
                row = await tokens.revoke_token(s, args.name, now)
                await audit.append(
                    s, actor=actor, action="token.revoke", now=now, target_type="api_token", target_id=row.name,
                )  # fmt: skip
                print(f"已吊销 {row.name}")
                return 0
            if args.cmd == "user-list":
                for u in (await s.scalars(select(AppUser).order_by(AppUser.username))).all():
                    print(json.dumps({
                        "username": u.username, "auth_source": u.auth_source, "roles": list(u.roles),
                        "active": u.active,
                        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                    }, ensure_ascii=False))  # fmt: skip
                return 0
            if args.cmd == "user-add":
                user = await security.create_user(
                    s, username=args.username, password=_read_password(), roles=args.role,
                    now=now, display_name=args.display_name,
                )  # fmt: skip
                detail: dict[str, Any] = {"username": user.username, "roles": list(user.roles)}
                action = "user.create"
            elif args.cmd == "user-passwd":
                await security.set_password(s, args.username, _read_password())
                detail, action = {"username": args.username}, "user.password"
            else:
                await security.set_active(s, args.username, False)
                detail, action = {"username": args.username}, "user.disable"
            await audit.append(
                s, actor=actor, action=action, now=now, target_type="app_user",
                target_id=args.username, detail=detail,
            )  # fmt: skip
        print(f"{action}：{args.username}")
        return 0
    except (security.UserError, tokens.TokenError) as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    finally:
        await engine.dispose()


async def _llm_command(args: argparse.Namespace, settings: Settings, rules: ProjectRules) -> int:
    if not settings.database_url:
        print("错误：需要设置环境变量 OPTI_DATABASE_URL", file=sys.stderr)
        return 2
    keyring = Keyring.from_env(state_dir=settings.state_dir)
    engine = make_engine(settings.database_url)
    try:
        if args.cmd == "rekey":
            if keyring is None:
                print("错误：未配置或无法解析 OPTI_ENCRYPTION_KEY", file=sys.stderr)
                return 2
            try:
                async with make_sessionmaker(engine).begin() as s:
                    llm_changed = await llm_runtime.rekey(s, keyring)
                    secret_changed = await config_secrets.rekey(s, keyring)
                    await audit.append(
                        s, actor=f"cli:{getpass.getuser()}", action="secrets.rekey",
                        now=datetime.now(UTC), detail={"fields": llm_changed + secret_changed},
                    )  # fmt: skip
            except SecretError as e:
                print(f"错误：{e}；没有改动任何字段", file=sys.stderr)
                return 2
            # 连接器凭据存于 config_secret（kind connectors），已包含在配置密钥里
            print(
                f"已用当前主密钥重新加密 {llm_changed} 个大模型字段、{secret_changed} 个配置密钥"
                "（含连接器凭据）"
            )
            return 0
        async with make_sessionmaker(engine)() as s:
            rt = await llm_runtime.load(s, keyring, include_disabled=True)  # 启用前也能检查与评测
        if rt.cfg is None:
            if rt.problem is None:
                msg = "还没有主用供应商：请在页面「大模型研判」中添加供应商并选为主用"
                if args.cmd == "llm-check":
                    print(msg)
                    return 0
            else:
                msg = f"大模型研判不可用：{rt.problem}"
            print(msg, file=sys.stderr)
            return 2
        org = current_organization()
        async with llm_runtime.adjudicator(rt) as adj:
            assert adj is not None
            if args.cmd == "llm-check":
                try:
                    answer = await adj.answer(llm_runtime.sample_input(rules, org))
                except AdjudicationError as e:
                    print(f"大模型调用失败：{e}", file=sys.stderr)
                    return 2
                print(json.dumps({"provider": answer.provider, "backend": answer.backend,
                                  "model": answer.model, **answer.assessment.public()},
                                 ensure_ascii=False))  # fmt: skip
                return 0
            if args.cmd == "eval-code":
                code = await evaluate_code_llm(
                    rules, load_code_cases(args.file), adj,
                    organization=org.name, short_name=org.short_name,
                )  # fmt: skip
                print(json.dumps(code.to_dict(), ensure_ascii=False, indent=2))
                return 0
            base, with_llm = await evaluate_texts_llm(
                rules, load_text_cases(args.file), adj,
                organization=org.name, short_name=org.short_name,
            )  # fmt: skip

        def summary(ev: TextEvaluation) -> dict[str, Any]:
            return {
                "recall": round(ev.recall, 3),
                "fp_rate": round(ev.fp_rate, 3),
                "passed": ev.passed,
                "failures": ev.failures,
            }

        print(json.dumps({"rules": summary(base), "rules_llm": summary(with_llm)},
                         ensure_ascii=False, indent=2))  # fmt: skip
        return 0 if with_llm.passed else 1
    finally:
        await engine.dispose()


async def amain(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = _settings(args)
    try:
        if settings.database_url and getattr(args, "rules", None) is None:
            rules = (await load_current(settings)).rules
        else:
            rules = load_project_rules(settings.rules_path)
    except ConfigError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2

    if args.cmd == "logo-hash":
        try:
            if args.image.stat().st_size > MAX_REFERENCE_BYTES:
                raise ValueError("图片文件过大")
            fingerprint = dhash_bytes(args.image.read_bytes())
            if not hash_usable(fingerprint):
                raise ValueError("图片指纹区分力不足，请选择轮廓更清晰的 Logo 图片")
        except (OSError, ValueError) as e:
            print(f"错误：{e}", file=sys.stderr)
            return 2
        print(json.dumps({"dhash64": fingerprint}))
        return 0

    if args.cmd == "favicon-hash":
        try:
            if args.image.stat().st_size > MAX_ICON_BYTES:
                raise ValueError("站点图标文件过大")
            icon_fingerprint = favicon_fingerprint(args.image.read_bytes())
            if icon_fingerprint is None:
                raise ValueError("仅支持 16–131072 字节的 ICO、PNG、JPEG、GIF 或 WebP 图标")
        except (OSError, ValueError) as e:
            print(f"错误：{e}", file=sys.stderr)
            return 2
        print(json.dumps({"mmh3": icon_fingerprint["mmh3"], "sha256": icon_fingerprint["sha256"]}))
        return 0

    if args.cmd == "match-domain":
        matcher = DomainMatcher(rules.domains)
        for raw in args.domains:
            print(json.dumps(_domain_result(matcher, raw), ensure_ascii=False))
        return 0
    if args.cmd == "match-text":
        hits = TextMatcher(rules).match(sys.stdin.read())
        print(json.dumps([asdict(h) for h in hits], ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "encryption-key-gen":
        print(generate_key())
        print(
            "写入 .env：OPTI_ENCRYPTION_KEY=<上面的值>（API 与 worker 都需要）；请离线备份。",
            file=sys.stderr,
        )
        return 0
    if args.cmd in ("llm-check", "rekey", "eval-code") or (args.cmd == "eval-texts" and args.llm):
        return await _llm_command(args, settings, rules)
    if args.cmd == "siem-test":
        snapshot = await load_current(settings)
        sharing = snapshot.sharing
        siem_secrets = snapshot.secrets("sharing")
        http = RateLimitedHttpClient()
        try:
            senders, problems = build_senders(
                sharing.siem,
                http,
                signing_key=siem_secrets.get("siem_signing_key"),
                webhook_token=siem_secrets.get("siem_webhook_token"),
            )
            if problems:
                print("；".join(problems), file=sys.stderr)
            if not senders:
                if not problems:
                    print("SIEM 渠道未启用")
                return 2 if problems else 0
            event = SiemEvent(
                alert_id=0,
                project_id=rules.project,
                severity="info",
                category="test",
                score=0,
                reasons=("siem-test",),
                entity_type="domain",
                entity_value="opti-siem-test.invalid",
                title="Open-TI SIEM 连通性测试",
                created_at=datetime.now(UTC),
                link=snapshot.alerting.public_base_url,
            )
            failed = 0
            for sender in senders:
                try:
                    ok = await sender.send([event]) == [0]
                except Exception as e:
                    print(f"{sender.name}：失败（{type(e).__name__}）", file=sys.stderr)
                    ok = False
                if ok:
                    print(f"{sender.name}：已发送")
                failed += not ok
            return 2 if failed or problems else 0
        finally:
            await http.aclose()
    if args.cmd == "eval-texts":
        evaluation = evaluate_texts(rules, load_text_cases(args.file))
        print(json.dumps({
            "positives": evaluation.positives,
            "recall": round(evaluation.recall, 3),
            "negatives": evaluation.negatives,
            "false_positives": evaluation.false_positives,
            "fp_rate": round(evaluation.fp_rate, 3),
            "passed": evaluation.passed,
            "failures": evaluation.failures,
        }, ensure_ascii=False, indent=2))  # fmt: skip
        return 0 if evaluation.passed else 1
    if args.cmd == "eval":
        sets = run_golden(rules, args.dir)
        passed = all(s.passed for s in sets)
        print(
            json.dumps(
                {"passed": passed, "sets": [s.to_dict() for s in sets]},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if passed else 1
    if args.cmd == "vendors-test":
        vendor_matcher = PartyMatcher(
            current_organization(),
            rules.domains.official,
            (await load_current(settings)).vendors
            if settings.database_url
            else load_vendors(settings.vendors_path),
        )
        vendor_hits = [
            {
                "kind": m.party.kind,
                "id": m.party.id,
                "name": m.party.name,
                "tier": m.party.tier,
                "owner": m.party.owner,
                "how": m.how,
                "detail": m.detail,
            }
            for m in vendor_matcher.match(args.victim, args.domain)
        ]
        print(json.dumps(vendor_hits, ensure_ascii=False))
        return 0
    if args.cmd == "software-check":
        try:
            inventory = load_software(settings.software_path)
        except (ValidationError, yaml.YAMLError) as e:
            print(f"软件清单有误（{settings.software_path}）：{e}", file=sys.stderr)
            return 2
        print(f"软件清单有效：{len(inventory.software)} 个软件（{settings.software_path}）")
        return 0

    paths = RuntimePaths(config_dir=settings.config_dir, state_dir=settings.state_dir)
    try:
        if args.cmd in USER_COMMANDS:
            if not settings.database_url:
                print("错误：需要设置环境变量 OPTI_DATABASE_URL", file=sys.stderr)
                return 2
            return await _user_command(args, settings)
        if args.cmd in DB_COMMANDS:
            if not settings.database_url:
                print("错误：需要设置环境变量 OPTI_DATABASE_URL", file=sys.stderr)
                return 2
            return await _db_command(args, settings)
        registry = Registry()
        if args.cmd == "connectors":
            return _cmd_connectors(registry, paths)
        if args.cmd == "collect":
            return await _cmd_collect(args, rules, registry, paths)
        if args.cmd == "enrich":
            return await _cmd_enrich(args, rules, registry, paths)
        return await _cmd_tranco_refresh(registry, paths)
    except ManifestError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    except (ConnectorBlocked, MissingCredential) as e:
        print(f"错误：连接器不可运行：{e}", file=sys.stderr)
        return 3


def _run_service(args: argparse.Namespace, settings: Settings) -> int:
    if args.cmd == "canary-snippet":
        token = os.environ.get("OPTI_SECRET_INTAKE_CANARY_TOKEN") or ""
        rules = asyncio.run(load_current(settings)).rules
        js, css = canary_snippets(args.base_url, token, rules.domains.official)
        print("<!-- 放在官网页面的 </body> 之前 -->")
        print(js)
        print("/* 可选：放在不常加载的样式表中 */")
        print(css)
        return 0
    if args.cmd in ("intake", "syslog"):
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
        )
        install_log_filter()
        require_mask_key()
        asyncio.run(_run_intake(settings) if args.cmd == "intake" else _run_syslog(settings))
        return 0
    if args.cmd == "api-schema":
        deps = ApiDeps(
            settings=settings,
            config=ConfigRuntime.static(load_project_rules(settings.rules_path)),
            sessions=async_sessionmaker(),
            store=None,
        )
        print(json.dumps(openapi_schema(deps), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.cmd == "pki-dev":
        make_dev_pki(args.out, server_names=args.server, nodes=args.node)
        print(
            f"已生成 {args.out}/ca.pem、gateway.pem 与 "
            + "、".join(f"node-{n}.pem" for n in args.node)
        )
        return 0
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    install_log_filter()  # 设计文档 2.3：日志中不出现凭据原值
    if args.cmd in ("api", "gateway", "worker", "collector", "scheduler"):
        require_mask_key()  # fail closed：长驻服务缺少遮蔽密钥时拒绝启动
    if args.cmd == "api":
        serve_api(settings)
        return 0
    if args.cmd == "gateway":
        serve(settings)
        return 0
    if args.cmd == "sandbox":
        import uvicorn

        from opti.sandbox.service import PlaywrightCapture, create_sandbox

        app = create_sandbox(
            PlaywrightCapture(
                allow_private=args.allow_private,
                ocr_enabled=os.environ.get("OPTI_SANDBOX_OCR_ENABLED", "false").lower()
                in ("1", "true", "yes"),
            )
        )
        uvicorn.run(app, host=args.host, port=args.port, log_level="info", server_header=False)
        return 0
    collector_settings = CollectorSettings.from_env()

    async def run_collector() -> None:
        client = collector_settings.client()
        try:
            await CollectorNode(collector_settings, client).run()
        finally:
            await client.aclose()

    asyncio.run(run_collector())
    return 0


async def _run_intake(settings: Settings) -> None:
    import uvicorn
    from redis.asyncio import Redis

    from opti.collector.node import CollectorSettings
    from opti.configs.edge import EdgeRules, gateway_fetch, valkey_fetch
    from opti.configs.runtime import process_name
    from opti.intake.app import IntakeDeps, create_intake
    from opti.intake.forward import direct_forwarder, gateway_forwarder

    token = os.environ.get("OPTI_SECRET_INTAKE_CANARY_TOKEN") or ""
    key = os.environ.get("OPTI_SECRET_INTAKE_REPORT_KEY") or ""
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", token) or len(key) < 32:
        raise ValueError(
            "需要 OPTI_SECRET_INTAKE_CANARY_TOKEN（≥16 位）与 OPTI_SECRET_INTAKE_REPORT_KEY（≥32 字符）"
        )
    if settings.database_url:
        raise ValueError("入口不得设置 OPTI_DATABASE_URL；只配置队列或采集网关")
    mode = os.environ.get("OPTI_INTAKE_FORWARD", "direct")
    if mode not in ("direct", "gateway"):
        raise ValueError("OPTI_INTAKE_FORWARD 只能是 direct/gateway")
    if mode == "direct" and not settings.broker_url:
        raise ValueError("direct 入口需要 OPTI_BROKER_URL（持久任务队列）")
    rules = load_project_rules(settings.rules_path)
    if mode == "gateway":
        client = CollectorSettings.from_env().client()
        forward, close = gateway_forwarder(client)
        edge = EdgeRules(
            rules, gateway_fetch(client), process=process_name("intake"), interval=60.0
        )
    else:
        from opti.pipeline.broker import broker

        forward, close = direct_forwarder()
        await broker.startup()
        assert settings.broker_url is not None  # direct 模式已在上面拒绝空队列地址
        kv = Redis.from_url(settings.broker_url, decode_responses=True)
        edge = EdgeRules(rules, valkey_fetch(kv), process=process_name("intake"), status=kv)
    await edge.refresh()
    deps = IntakeDeps(
        rules=rules, forward=forward, canary_token=token, report_key=key.encode(),
        prefix=os.environ.get("OPTI_INTAKE_PREFIX", "/ti-intake"), edge=edge,
    )  # fmt: skip
    config = uvicorn.Config(
        create_intake(deps),
        host=os.environ.get("OPTI_INTAKE_HOST", "0.0.0.0"),
        port=int(os.environ.get("OPTI_INTAKE_PORT", "8100")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("OPTI_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        server_header=False,
        access_log=False,
    )
    refresher = asyncio.create_task(edge.run())
    try:
        await uvicorn.Server(config).serve()
    finally:
        refresher.cancel()
        await close()


async def _run_syslog(settings: Settings) -> None:
    if not settings.broker_url:
        raise ValueError("syslog 需要 OPTI_BROKER_URL（持久任务队列）")
    import ssl

    from redis.asyncio import Redis

    from opti.configs.edge import EdgeRules, valkey_fetch
    from opti.intake.forward import direct_forwarder
    from opti.pipeline.broker import broker
    from opti.referer.logs import RefererAggregator
    from opti.referer.server import SyslogServer

    cert, key = os.environ.get("OPTI_SYSLOG_TLS_CERT"), os.environ.get("OPTI_SYSLOG_TLS_KEY")
    ctx = None
    if bool(cert) != bool(key):
        raise ValueError("OPTI_SYSLOG_TLS_CERT 与 OPTI_SYSLOG_TLS_KEY 必须同时配置")
    if cert and key:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert, key)
    rules = load_project_rules(settings.rules_path)
    agg = RefererAggregator(rules, min_hits=int(os.environ.get("OPTI_SYSLOG_MIN_HITS", "3")))
    kv = Redis.from_url(settings.broker_url, decode_responses=True)
    edge = EdgeRules(rules, valkey_fetch(kv), process=process_name("syslog"), status=kv)
    edge.subscribe(agg.update_rules)
    await edge.refresh()
    refresher = asyncio.create_task(edge.run())
    forward, close = direct_forwarder()
    await broker.startup()
    server = SyslogServer(
        agg, forward, host=os.environ.get("OPTI_SYSLOG_HOST", "0.0.0.0"),
        port=int(os.environ.get("OPTI_SYSLOG_PORT", "6514")), ssl_context=ctx,
    )  # fmt: skip
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await server.start()
        await stop.wait()
    finally:
        refresher.cancel()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        try:
            await server.close()
            await server.flush_now()
        finally:
            await close()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd in SERVICE_COMMANDS:
        return _run_service(args, _settings(args))
    return asyncio.run(amain(argv))


if __name__ == "__main__":
    raise SystemExit(main())
