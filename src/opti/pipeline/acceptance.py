"""MVP 验收报告（设计文档 1.4、20）：逐项给出 达标 / 未达标 / 样本不足 / 需人工确认，输出 Markdown 与 JSON。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.evaluation import SetResult
from opti.core.metrics import MttdStat
from opti.core.watcher import Comparison
from opti.db.models import Alert, AlertFinding, Entity, Evidence, Finding, Takedown
from opti.pipeline import metrics
from opti.takedown.stats import StatRow, compute

Status = Literal["pass", "fail", "insufficient", "manual"]
STATUS_LABEL = {
    "pass": "达标",
    "fail": "未达标",
    "insufficient": "样本不足",
    "manual": "需人工确认",
}
MIN_TRIAGED = 10
PRECISION_MIN = 0.5
FREE_SOURCES_MIN = 15
EVIDENCE_MIN = 0.9


@dataclass(frozen=True)
class Check:
    key: str
    title: str
    target: str
    value: str
    status: Status
    note: str = ""


def _pct(part: int, total: int) -> str:
    return f"{part / total * 100:.1f}%（{part} / {total}）"


def mttd_check(stat: MttdStat | None, key: str, title: str) -> Check:
    target = f"中位数 < {stat.target_hours:g} 小时" if stat else "—"
    if stat is None or stat.count == 0 or stat.median_hours is None:
        return Check(
            key,
            title,
            target,
            "无样本",
            "insufficient",
            "需要该来源产生的告警（见运行手册的端到端金丝雀）",
        )
    ok = stat.median_hours < stat.target_hours
    value = f"中位数 {stat.median_hours:g} 小时（{stat.count} 个样本）"
    return Check(key, title, target, value, "pass" if ok else "fail")


async def precision_check(session: AsyncSession, project: str, since: datetime) -> Check:
    rows = await session.execute(
        select(Alert.triage_verdict, func.count())
        .where(
            Alert.project_id == project,
            Alert.created_at >= since,
            Alert.triage_verdict.is_not(None),
        )
        .group_by(Alert.triage_verdict)
    )
    counts = {str(v): int(n) for v, n in rows.all()}
    total, tp = sum(counts.values()), counts.get("true_positive", 0)
    title, target = "告警精确率（人工确认为真 / 已研判告警）", "≥ 50%"
    if total < MIN_TRIAGED:
        return Check(
            "precision",
            title,
            target,
            f"已研判 {total} 条",
            "insufficient",
            f"至少需要 {MIN_TRIAGED} 条研判结论",
        )
    return Check(
        "precision",
        title,
        target,
        _pct(tp, total),
        "pass" if tp / total >= PRECISION_MIN else "fail",
    )


async def evidence_check(session: AsyncSession, project: str, since: datetime) -> Check:
    rows = (
        await session.execute(
            select(Alert.id, Entity.type, Entity.value, Entity.enrichment,
                   Finding.match["platform"].astext, Finding.id)
            .join(AlertFinding, AlertFinding.alert_id == Alert.id)
            .join(Finding, Finding.id == AlertFinding.finding_id)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(
                Alert.project_id == project, Alert.created_at >= since,
                Alert.severity.in_(("critical", "high")), Entity.type.in_(("domain", "url")),
            )
        )
    ).all()  # fmt: skip
    title, target = "证据完整率（High 及以上告警含截图 + RDAP + DNS）", "≥ 90%"
    if not rows:
        return Check("evidence", title, target, "无 High 及以上告警", "insufficient")
    shots = set(
        (
            await session.scalars(
                select(Evidence.alert_id).where(
                    Evidence.alert_id.in_([r[0] for r in rows]), Evidence.kind == "screenshot"
                )
            )
        ).all()
    )
    # 分析员上传的截图同样算截图，按发现计：平台链接升级为新告警后沿用此前的上传
    uploads = set(
        (
            await session.scalars(
                select(Evidence.finding_id).where(
                    Evidence.finding_id.in_([r[5] for r in rows]), Evidence.kind == "upload"
                )
            )
        ).all()
    )
    hosts = {urlsplit(v).hostname for _, t, v, _, _, _ in rows if t == "url"} - {None}
    host_enrichment = {
        e.value: e.enrichment or {}
        for e in await session.scalars(select(Entity).where(Entity.type == "domain", Entity.value.in_(hosts)))
    } if hosts else {}  # fmt: skip
    complete_alerts: set[int] = set()
    for alert_id, etype, value, enrichment, platform, finding_id in rows:
        data = enrichment or {}
        if platform:  # 平台链接（linkedin.com 等）不查平台域名的 RDAP/DNS，只要求截图
            complete = True
        elif etype == "url":
            host = urlsplit(value).hostname or ""
            direct = {
                key
                for key in ("rdap", "dns")
                if isinstance(data.get(key), dict)
                and data[key].get("target_type") == "domain"
                and data[key].get("target_value") == host
            }
            fallback = set(host_enrichment.get(host, {}))
            complete = {"rdap", "dns"} <= direct | fallback
        else:
            complete = "rdap" in data and "dns" in data
        if (alert_id in shots or finding_id in uploads) and complete:
            complete_alerts.add(alert_id)
    total = len({alert_id for alert_id, *_ in rows})
    ok = len(complete_alerts) / total >= EVIDENCE_MIN
    return Check(
        "evidence", title, target, _pct(len(complete_alerts), total), "pass" if ok else "fail"
    )


async def mttr_check(session: AsyncSession, project: str, since: datetime) -> Check:
    rows = (
        await session.execute(
            select(Takedown, Finding.first_seen)
            .join(Finding, Finding.id == Takedown.finding_id)
            .where(Takedown.project_id == project, Takedown.created_at >= since)
        )
    ).all()
    mttr = compute(
        [
            StatRow(td.state, str(td.target.get("name") or ""), str(td.target.get("kind") or ""),
                    td.submitted_at, td.acknowledged_at, td.resolved_at, first_seen)
            for td, first_seen in rows
        ]
    )["mttr_hours"]  # fmt: skip
    title, target = "下架 MTTR（发现到下架，中位数）", "跟踪统计"
    if mttr is None:
        return Check("mttr", title, target, "无已完成的下架", "insufficient")
    return Check("mttr", title, target, f"{mttr:g} 小时", "pass")


def source_checks(catalog: Sequence[Mapping[str, Any]]) -> tuple[Check, Check]:
    runnable = [
        c for c in catalog if c.get("runnable") is True and "enricher" not in c.get("kind", [])
    ]
    unknown = [
        str(c["id"])
        for c in catalog
        if c.get("runnable") is None and "enricher" not in c.get("kind", [])
    ]
    free = [str(c["id"]) for c in runnable if c.get("tier") == "free"]
    paid = [str(c["id"]) for c in runnable if c.get("tier") == "paid"]
    freemium = [str(c["id"]) for c in runnable if c.get("tier") == "freemium"]
    note = f"等待采集节点上报：{', '.join(unknown)}" if unknown else ""
    free_status: Status = (
        "pass"
        if len(free) >= FREE_SOURCES_MIN
        else ("insufficient" if len(free) + len(unknown) >= FREE_SOURCES_MIN else "fail")
    )
    sources = Check("free_sources", "覆盖渠道数（可运行的免费数据源）", f"≥ {FREE_SOURCES_MIN} 个", str(len(free)),
                    free_status, note)  # fmt: skip
    paid_note = "; ".join(x for x in (f"付费：{', '.join(paid)}" if paid else "",
                                      f"免费额度：{', '.join(freemium)}（确认在免费额度内）" if freemium else "") if x)  # fmt: skip
    paid_status: Status = "fail" if paid else "manual" if freemium else "pass"
    zero_paid = Check("zero_paid", "默认启用的连接器零付费运行", "没有可运行的付费连接器",
                      f"{len(paid)} 个付费 / {len(freemium)} 个免费额度", paid_status, paid_note)  # fmt: skip
    return sources, zero_paid


def golden_checks(golden: Sequence[SetResult]) -> tuple[Check, Check]:
    by_name = {g.name: g for g in golden}
    domains = by_name.get("domains")
    if domains is None or domains.positives == 0:
        recall = Check("recall", "召回率（金标准集，仿冒域名）", "≥ 70%", "未运行", "insufficient")
    else:
        recall = Check("recall", "召回率（金标准集，仿冒域名）", "≥ 70%", f"{domains.recall * 100:.1f}%",
                       "pass" if domains.recall >= domains.recall_min else "fail")  # fmt: skip
    failed = [g.name for g in golden if not g.passed]
    missing = [
        name
        for name in ("domains", "urls", "texts")
        if name not in by_name or by_name[name].positives == 0 or by_name[name].negatives == 0
    ]
    all_ok = not failed and not missing
    regression_status: Status = "fail" if failed else "insufficient" if missing else "pass"
    regression = Check("golden", "金标准集全量回归（域名、URL、文本）", "全部达标",
                       "全部达标" if all_ok else f"未达标：{', '.join(failed)}" if failed else f"样本不足：{', '.join(missing)}", regression_status)  # fmt: skip
    return recall, regression


def watcher_check(comparison: Comparison | None) -> Check:
    title, target = "与 Watcher 对照（漏报候选）", "0 个，或逐个复核"
    if comparison is None:
        return Check(
            "watcher", title, target, "未提供 Watcher 导出", "manual", "用 --watcher 指定导出文件"
        )
    if not comparison.both and not comparison.watcher_only:
        return Check("watcher", title, target, "Watcher 导出为空", "insufficient")
    missed = [w["domain"] for w in comparison.watcher_only if w["status"] == "not_found"]
    summary = comparison.to_dict()["summary"]
    value = f"共同 {summary['both']} / 仅本平台 {summary['ours_only']} / 漏报候选 {len(missed)}"
    if not missed:
        return Check("watcher", title, target, value, "pass")
    return Check("watcher", title, target, value, "manual", f"逐个复核：{', '.join(missed[:20])}")


async def run(
    session: AsyncSession,
    *,
    rules: ProjectRules,
    catalog: Sequence[Mapping[str, Any]],
    golden: Sequence[SetResult],
    watcher: Comparison | None,
    now: datetime,
    days: int,
) -> list[Check]:
    since = now - timedelta(days=days)
    stats = {
        m.source: m for m in await metrics.mttd(session, rules.project, since=since, until=now)
    }
    recall, regression = golden_checks(golden)
    sources, zero_paid = source_checks(catalog)
    return [
        mttd_check(stats.get("ct"), "mttd_ct", "仿冒域名 MTTD（CT 证书到告警）"),
        mttd_check(stats.get("nrd"), "mttd_nrd", "仿冒域名 MTTD（注册到告警，NRD / dnstwist）"),
        await precision_check(session, rules.project, since),
        recall,
        await mttr_check(session, rules.project, since),
        sources,
        await evidence_check(session, rules.project, since),
        Check(
            "availability",
            "平台可用性",
            "≥ 99%",
            "—",
            "manual",
            "以使用机构的监控系统为准，平台内无法测量",
        ),
        zero_paid,
        regression,
        watcher_check(watcher),
    ]


def _overall(checks: Sequence[Check]) -> str:
    if any(c.status == "fail" for c in checks):
        return "fail"
    if any(c.status == "manual" for c in checks):
        return "manual"
    if any(c.status == "insufficient" for c in checks):
        return "insufficient"
    return "pass"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(checks: Sequence[Check], *, project: str, now: datetime, days: int) -> str:
    counts = {s: sum(c.status == s for c in checks) for s in STATUS_LABEL}
    summary = "、".join(f"{STATUS_LABEL[s]} {n} 项" for s, n in counts.items() if n)
    lines = [
        "# MVP 验收报告", "",
        f"- 项目：{project}", f"- 统计时段：最近 {days} 天（截至 {now:%Y-%m-%d %H:%M} UTC）", f"- 结论：{summary}", "",
        "| 指标 | 目标 | 实际 | 结论 | 说明 |", "|---|---|---|---|---|",
        *(f"| {_cell(c.title)} | {_cell(c.target)} | {_cell(c.value)} | {STATUS_LABEL[c.status]} | {_cell(c.note)} |"
          for c in checks),
        "", "指标定义见设计文档 1.4；样本不足与需人工确认的项目须在交付报告中说明。",
    ]  # fmt: skip
    return "\n".join(lines) + "\n"


def to_json(checks: Sequence[Check], *, project: str, now: datetime, days: int) -> dict[str, Any]:
    return {
        "project": project, "generated_at": now.isoformat(), "days": days, "overall": _overall(checks),
        "checks": [asdict(c) for c in checks],
    }  # fmt: skip
