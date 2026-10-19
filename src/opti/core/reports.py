"""日报、周报与月报的渲染（设计文档 9.2、13、14）：报告内容（JSON）→ 标题、HTML、纯文本与推送摘要。

域名与 URL 一律去链接化，只链接回平台；HTML 中的所有文本都经过转义。报告不含个人信息。
"""

from __future__ import annotations

import html
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

KINDS = ("daily", "weekly", "monthly")
MAX_LINES = 15
CATEGORY_NAMES: dict[str, dict[str, str]] = {
    "zh-CN": {
        "phishing_site": "钓鱼网站", "typosquat_domain": "仿冒域名", "unapproved_certificate": "未经批准的证书",
        "reported_phishing": "被举报的钓鱼", "clone_site": "克隆站", "email_spoofing": "冒用邮件发件",
        "credential_exposure": "凭据暴露", "ransomware_mention": "勒索泄露站提及", "data_leak": "数据泄露",
        "secret_leak": "密钥泄露", "brand_mention": "一般提及", "negative_press": "负面舆情",
        "fraud_scam": "冒名诈骗", "threat_intel": "威胁情报", "vulnerability": "已被利用漏洞",
        "impersonation_account": "冒充账号",
    },
    "en-US": {
        "phishing_site": "Phishing site", "typosquat_domain": "Lookalike domain",
        "unapproved_certificate": "Unapproved certificate", "reported_phishing": "Reported phishing",
        "clone_site": "Cloned site", "email_spoofing": "Email spoofing", "credential_exposure": "Credential exposure",
        "ransomware_mention": "Ransomware leak-site mention", "data_leak": "Data leak", "secret_leak": "Secret leak",
        "brand_mention": "Brand mention", "negative_press": "Negative press", "fraud_scam": "Impersonation scam",
        "threat_intel": "Threat intelligence", "vulnerability": "Known exploited vulnerability",
        "impersonation_account": "Impersonation account",
    },
}  # fmt: skip
LABELS: dict[str, dict[str, Any]] = {
    "zh-CN": {
        "daily": "威胁情报日报", "weekly": "威胁情报周报", "period": "统计周期", "overview": "概况",
        "findings": "新发现", "alerts": "新告警", "low_findings": "低级发现", "by_category": "按类别",
        "category": "类别", "alerts_daily": "中级告警汇总", "alerts_weekly": "本期告警",
        "news": "新闻与情报提及", "vulnerabilities": "已被利用漏洞（软件清单命中）", "low": "低级发现（前 10 条）",
        "triage": "研判反馈", "takedowns": "下架处置", "opened": "新建", "resolved": "完成", "none": "无",
        "view": "在平台中查看", "more": "另有 {n} 条，请在平台中查看", "colon": "：",
        "item": "[{severity}] {category}：{subject}（{score} 分）",
        "severity": {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息"},
        "verdict": {"true_positive": "真实威胁", "false_positive": "误报", "duplicate": "重复",
                    "benign_known": "已知无害", "out_of_scope": "不在范围"},
        "monthly": "威胁情报月报", "compare": "{now}（上月 {prev}，{delta}）",
        "by_category_monthly": "按类别（本月 / 上月告警）", "events": "重点事件（严重与高级告警）",
        "vulnerabilities_monthly": "已被利用漏洞（软件清单命中，共 {n} 条）",
        "mentions": "负面舆情与冒名诈骗提及（共 {n} 条）", "trend": "近 6 个月告警趋势", "month": "月份",
        "status": {"open": "待处理", "acknowledged": "处理中", "closed": "已关闭", "superseded": "已被取代"},
        "with_verdict": "{status}（{verdict}）", "with_takedown": "{status}· 下架：{state}",
        "takedown_state": {"draft": "草稿", "approved": "已审批", "submitted": "已提交", "acknowledged": "对方已受理",
                           "removed": "已下架", "rejected": "被拒绝", "cancelled": "已取消", "reappeared": "已复活"},
    },
    "en-US": {
        "daily": "Threat intelligence daily report", "weekly": "Threat intelligence weekly report",
        "period": "Period", "overview": "Overview", "findings": "New findings", "alerts": "New alerts",
        "low_findings": "Low findings", "by_category": "By category", "category": "Category",
        "alerts_daily": "Medium alerts", "alerts_weekly": "Alerts this period", "news": "News and intelligence mentions",
        "vulnerabilities": "Known exploited vulnerabilities (inventory matches)", "low": "Low findings (top 10)",
        "triage": "Triage feedback", "takedowns": "Takedowns", "opened": "Opened", "resolved": "Resolved",
        "none": "None", "view": "View in platform", "more": "{n} more, see the platform", "colon": ": ",
        "item": "[{severity}] {category}: {subject} ({score} pts)",
        "severity": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "verdict": {"true_positive": "True positive", "false_positive": "False positive", "duplicate": "Duplicate",
                    "benign_known": "Known benign", "out_of_scope": "Out of scope"},
        "monthly": "Threat intelligence monthly report", "compare": "{now} (prev. {prev}, {delta})",
        "by_category_monthly": "By category (alerts this month / last month)",
        "events": "Key events (critical and high alerts)",
        "vulnerabilities_monthly": "Known exploited vulnerabilities (inventory matches, {n} total)",
        "mentions": "Negative press and impersonation scam mentions ({n} total)",
        "trend": "Alert trend, last 6 months", "month": "Month",
        "status": {"open": "Open", "acknowledged": "In progress", "closed": "Closed", "superseded": "Superseded"},
        "with_verdict": "{status} ({verdict})", "with_takedown": "{status} · Takedown: {state}",
        "takedown_state": {"draft": "Draft", "approved": "Approved", "submitted": "Submitted",
                           "acknowledged": "Acknowledged", "removed": "Removed", "rejected": "Rejected",
                           "cancelled": "Cancelled", "reappeared": "Reappeared"},
    },
}  # fmt: skip
_STYLE = (
    "body{font-family:-apple-system,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;color:#1f2328;"
    "max-width:880px;margin:0 auto;padding:16px}h1{font-size:20px}h2{font-size:16px;margin-top:24px;"
    "border-bottom:1px solid #d0d7de;padding-bottom:4px}table{border-collapse:collapse}"
    "td,th{border:1px solid #d0d7de;padding:4px 8px;text-align:left;font-size:13px}.muted{color:#656d76}"
    "td.trend{width:240px}.bar{display:flex;height:10px}.bar span{display:block;height:10px}"
    ".critical{background:#cf222e}.high{background:#fb8500}.medium{background:#d4a72c}"
    # 打印 / 另存为 PDF：A4 页边距，小节标题不落在页尾，表格行与条目不跨页
    "@page{size:A4;margin:16mm}@media print{body{max-width:none;padding:0;-webkit-print-color-adjust:exact;"
    "print-color-adjust:exact}h2{break-after:avoid}tr,li{break-inside:avoid}a{color:inherit}}"
)


def empty_content(
    kind: str, *, start: datetime, end: datetime, language: str = "zh-CN", timezone: str = "UTC"
) -> dict[str, Any]:
    content: dict[str, Any] = {
        "kind": kind, "language": language, "timezone": timezone,
        "period_start": start.isoformat(), "period_end": end.isoformat(),
        "totals": {"findings": 0, "alerts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": [], "alerts": [], "news": [], "vulnerabilities": [],
    }  # fmt: skip
    if kind == "weekly":
        content.update(
            {
                "low": {"count": 0, "top": []},
                "triage": {},
                "takedowns": {"opened": 0, "resolved": 0},
            }
        )
    if kind == "monthly":
        content.update(
            {
                "previous": dict(content["totals"]),
                "counts": {"news": 0, "vulnerabilities": 0},
                "trend": [],
            }
        )
    return content


def month_label(moment: datetime, tz: ZoneInfo) -> str:
    return f"{moment.astimezone(tz):%Y-%m}"


def _labels(c: Mapping[str, Any]) -> dict[str, Any]:
    return LABELS.get(str(c.get("language")), LABELS["zh-CN"])


def _names(c: Mapping[str, Any]) -> dict[str, str]:
    return CATEGORY_NAMES.get(str(c.get("language")), CATEGORY_NAMES["zh-CN"])


def _tz(c: Mapping[str, Any]) -> ZoneInfo:
    try:
        return ZoneInfo(str(c.get("timezone") or "UTC"))
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def _time(value: Any, tz: ZoneInfo) -> str:
    return datetime.fromisoformat(str(value)).astimezone(tz).strftime("%Y-%m-%d %H:%M")


def _defang(value: str) -> str:
    return value.replace(".", "[.]")


def _subject(item: Mapping[str, Any]) -> str:
    s = str(item.get("subject") or "")
    return _defang(s)


def title(c: Mapping[str, Any]) -> str:
    if c["kind"] == "monthly":
        start = datetime.fromisoformat(str(c["period_start"]))
        return f"{_labels(c)['monthly']} {month_label(start, _tz(c))}"
    end = datetime.fromisoformat(str(c["period_end"])).astimezone(_tz(c))
    return f"{_labels(c)[str(c['kind'])]} {end:%Y-%m-%d}"


def _period(c: Mapping[str, Any]) -> str:
    tz = _tz(c)
    return f"{_time(c['period_start'], tz)} – {_time(c['period_end'], tz)}"


def facts(c: Mapping[str, Any]) -> list[tuple[str, str]]:
    labels, t = _labels(c), c["totals"]
    sev = labels["severity"]
    if c["kind"] == "monthly":
        prev = c.get("previous") or {}

        def compare(key: str) -> str:
            now, before = int(t[key]), int(prev.get(key, 0))
            delta = f"{now - before:+d}" if now != before else "0"
            return str(labels["compare"]).format(now=now, prev=before, delta=delta)

        return [
            (labels["period"], _period(c)),
            (labels["findings"], compare("findings")),
            (labels["alerts"], compare("alerts")),
            *((sev[s], compare(s)) for s in ("critical", "high", "medium")),
        ]
    return [
        (labels["period"], _period(c)),
        (labels["findings"], str(t["findings"])),
        (labels["alerts"], str(t["alerts"])),
        *((sev[s], str(t[s])) for s in ("critical", "high", "medium")),
        (labels["low_findings"], str(t["low"])),
    ]


def _alert_line(c: Mapping[str, Any], a: Mapping[str, Any]) -> str:
    labels, names = _labels(c), _names(c)
    line = str(labels["item"]).format(
        severity=labels["severity"].get(a.get("severity"), a.get("severity")),
        category=names.get(str(a.get("category")), str(a.get("category"))),
        subject=_subject(a),
        score=a.get("score"),
    )
    return f"{line} — {_status(c, a)}" if "status" in a else line


def _status(c: Mapping[str, Any], a: Mapping[str, Any]) -> str:
    """月报重点事件的处置状态：告警状态，附研判结论与最近一次下架的状态。"""
    labels = _labels(c)
    status = str(labels["status"].get(a.get("status"), a.get("status")))
    if a.get("verdict"):
        verdict = labels["verdict"].get(a["verdict"], a["verdict"])
        status = str(labels["with_verdict"]).format(status=status, verdict=verdict)
    if a.get("takedown"):
        state = labels["takedown_state"].get(a["takedown"], a["takedown"])
        status = str(labels["with_takedown"]).format(status=status, state=state)
    return status


def _trend_line(c: Mapping[str, Any], m: Mapping[str, Any]) -> str:
    labels = _labels(c)
    counts = " · ".join(
        f"{labels['severity'][s]} {m.get(s, 0)}" for s in ("critical", "high", "medium")
    )
    return f"{m.get('month')}{labels['colon']}{counts}"


def _trend_html(c: Mapping[str, Any]) -> str:
    labels, e = _labels(c), html.escape
    rows = c.get("trend") or []
    sevs = ("critical", "high", "medium")
    peak = max((sum(int(m.get(s, 0)) for s in sevs) for m in rows), default=0)
    out = [f"<h2>{e(labels['trend'])}</h2><table><tr><th>{e(labels['month'])}</th>"]
    out += [f"<th>{e(labels['severity'][s])}</th>" for s in sevs]
    out.append("<th></th></tr>")
    for m in rows:
        total = sum(int(m.get(s, 0)) for s in sevs)
        segments = "".join(
            f"<span class='{s}' style='width:{int(m.get(s, 0)) * 100 / total:.0f}%'></span>"
            for s in sevs
            if total and m.get(s)
        )
        bar = (
            f"<div class='bar' style='width:{total * 100 / peak:.0f}%'>{segments}</div>"
            if total
            else ""
        )
        out.append(f"<tr><th>{e(str(m.get('month')))}</th>")
        out += [f"<td>{int(m.get(s, 0))}</td>" for s in sevs]
        out.append(f"<td class='trend'>{bar}</td></tr>")
    out.append("</table>")
    return "".join(out)


def _vuln_line(c: Mapping[str, Any], v: Mapping[str, Any]) -> str:
    software = ", ".join(_defang(str(s)) for s in v.get("software") or [])
    sev = _labels(c)["severity"].get(v.get("severity"), v.get("severity"))
    return f"[{sev}] {_defang(str(v.get('cve') or ''))} {_defang(str(v.get('name') or ''))} — {software}".strip()


def _news_line(c: Mapping[str, Any], n: Mapping[str, Any]) -> str:
    labels, names = _labels(c), _names(c)
    host = urlsplit(str(n.get("url") or "")).hostname or ""
    source = " · ".join(x for x in (_defang(str(n.get("source") or "")), _defang(host)) if x)
    line = f"{names.get(str(n.get('category')), str(n.get('category')))}{labels['colon']}{_defang(str(n.get('title') or '-'))}"
    line += f" — {source}" if source else ""
    return line + (f"（{_defang(str(n['summary']))}）" if n.get("summary") else "")


def _sections(c: Mapping[str, Any]) -> list[tuple[str, list[tuple[str, Any]]]]:
    """（小节标题，[(文本行, 告警 ID 或 None)]）。"""
    labels, names = _labels(c), _names(c)
    if c["kind"] == "monthly":
        counts = c.get("counts") or {}
        return [
            (labels["by_category_monthly"], [
                (f"{names.get(x['category'], x['category'])}{labels['colon']}{x['alerts']} / {x['previous']}", None)
                for x in c.get("by_category") or []
            ]),
            (labels["events"], [(_alert_line(c, a), a.get("alert_id")) for a in c.get("alerts") or []]),
            (str(labels["vulnerabilities_monthly"]).format(n=counts.get("vulnerabilities", 0)),
             [(_vuln_line(c, v), v.get("alert_id")) for v in c.get("vulnerabilities") or []]),
            (str(labels["mentions"]).format(n=counts.get("news", 0)),
             [(_news_line(c, n), n.get("alert_id")) for n in c.get("news") or []]),
        ]  # fmt: skip
    out: list[tuple[str, list[tuple[str, Any]]]] = [
        (labels["by_category"], [
            (f"{names.get(x['category'], x['category'])}{labels['colon']}{x['findings']} / {x['alerts']}", None)
            for x in c.get("by_category") or []
        ]),
        (labels["alerts_daily" if c["kind"] == "daily" else "alerts_weekly"],
         [(_alert_line(c, a), a.get("alert_id")) for a in c.get("alerts") or []]),
        (labels["vulnerabilities"], [(_vuln_line(c, v), v.get("alert_id")) for v in c.get("vulnerabilities") or []]),
        (labels["news"], [(_news_line(c, n), n.get("alert_id")) for n in c.get("news") or []]),
    ]  # fmt: skip
    if c["kind"] == "weekly":
        low = c.get("low") or {}
        out.append((f"{labels['low']}（{low.get('count', 0)}）" if labels["colon"] == "：" else
                    f"{labels['low']} ({low.get('count', 0)})",
                    [(f"{names.get(x['category'], x['category'])}{labels['colon']}{_subject(x)}", None)
                     for x in low.get("top") or []]))  # fmt: skip
        verdicts = labels["verdict"]
        out.append((labels["triage"], [
            (f"{verdicts.get(k, k)}{labels['colon']}{n}", None) for k, n in sorted((c.get("triage") or {}).items())
        ]))  # fmt: skip
        td = c.get("takedowns") or {}
        out.append((labels["takedowns"], [
            (f"{labels['opened']}{labels['colon']}{td.get('opened', 0)}", None),
            (f"{labels['resolved']}{labels['colon']}{td.get('resolved', 0)}", None),
        ]))  # fmt: skip
    return out


def _alert_link(base_url: str, alert_id: Any) -> str | None:
    return f"{base_url.rstrip('/')}/alerts/{int(alert_id)}" if isinstance(alert_id, int) else None


def render_text(c: Mapping[str, Any], base_url: str, report_link: str) -> str:
    labels = _labels(c)
    lines = [title(c), f"{labels['period']}{labels['colon']}{_period(c)}", ""]
    lines += [f"{k}{labels['colon']}{v}" for k, v in facts(c)[1:]]
    if c["kind"] == "monthly":
        lines += ["", f"== {labels['trend']} =="]
        lines += [f"- {_trend_line(c, m)}" for m in c.get("trend") or []] or [f"- {labels['none']}"]
    for heading, rows in _sections(c):
        lines += ["", f"== {heading} =="]
        for text, alert_id in rows or [(labels["none"], None)]:
            link = _alert_link(base_url, alert_id)
            lines.append(f"- {text}" + (f"  {link}" if link else ""))
    lines += ["", f"{labels['view']}{labels['colon']}{report_link}"]
    return "\n".join(lines) + "\n"


def render_html(c: Mapping[str, Any], base_url: str, report_link: str) -> str:
    labels, e = _labels(c), html.escape
    out = [
        f"<!doctype html><html lang='{e(str(c.get('language') or 'zh-CN'))}'><head><meta charset='utf-8'>"
        f"<title>{e(title(c))}</title><style>{_STYLE}</style></head><body>",
        f"<h1>{e(title(c))}</h1><p class='muted'>{e(labels['period'])}{e(labels['colon'])}{e(_period(c))}</p>",
        f"<h2>{e(labels['overview'])}</h2><table>",
        *(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in facts(c)[1:]),
        "</table>",
    ]
    if c["kind"] == "monthly":
        out.append(_trend_html(c))
    for heading, rows in _sections(c):
        out.append(f"<h2>{e(heading)}</h2><ul>")
        for text, alert_id in rows or [(labels["none"], None)]:
            link = _alert_link(base_url, alert_id)
            anchor = f" <a href='{e(link)}'>{e(labels['view'])}</a>" if link else ""
            out.append(f"<li>{e(text)}{anchor}</li>")
        out.append("</ul>")
    out.append(f"<p><a href='{e(report_link)}'>{e(labels['view'])}</a></p></body></html>")
    return "".join(out)


@dataclass(frozen=True)
class ReportView:
    report_id: int
    kind: str
    title: str
    link: str
    facts: tuple[tuple[str, str], ...]
    lines: tuple[str, ...]  # 推送卡片中的重点条目（已去链接化，最多 MAX_LINES 条加一行"另有 n 条"）
    text: str
    html: str


def report_view(report_id: int, c: Mapping[str, Any], base_url: str) -> ReportView:
    link = f"{base_url.rstrip('/')}/reports/{report_id}"
    items = [_alert_line(c, a) for a in c.get("alerts") or []]
    items += [_vuln_line(c, v) for v in c.get("vulnerabilities") or []]
    items += [_news_line(c, n) for n in c.get("news") or []]
    lines = items[:MAX_LINES]
    if len(items) > MAX_LINES:
        lines.append(str(_labels(c)["more"]).format(n=len(items) - MAX_LINES))
    return ReportView(
        report_id=report_id, kind=str(c["kind"]), title=title(c), link=link, facts=tuple(facts(c)),
        lines=tuple(lines), text=render_text(c, base_url, link), html=render_html(c, base_url, link),
    )  # fmt: skip
