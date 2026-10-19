"""Jira / ServiceNow 工单的标题、正文与评论（设计 2026-10-16）：先生成结构，再渲染成 ADF 或纯文本。

全部文字经 mask_text；域名去链接化，只有平台链接可点击。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from opti.alerting.views import CATEGORY_LABEL, SEVERITY_LABEL, AlertView, defang
from opti.core.secret_guard import mask_text

# Jira 描述 / 评论上限 32767 字符，ServiceNow description 默认 4000：名单只列前 100 个
MAX_LISTED_ACCOUNTS = 100


@dataclass(frozen=True)
class Content:
    heading: str | None  # 评论首行；建单正文为 None
    facts: tuple[tuple[str, str], ...]
    accounts: tuple[str, ...]  # 只在 include_accounts 时非空
    link: str


def title(view: AlertView, limit: int) -> str:
    severity = SEVERITY_LABEL.get(view.severity, view.severity)
    category = CATEGORY_LABEL.get(view.category, view.category)
    text = mask_text(f"[Open-TI][{severity}] {category}：{defang(view.domain)}")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _exposure(extra: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    ex = (extra or {}).get("exposure")
    return ex if isinstance(ex, Mapping) else None


def _exposure_facts(ex: Mapping[str, Any], include_accounts: bool) -> list[tuple[str, str]]:
    classes = ex.get("data_classes") or []
    facts = [
        ("来源", str(ex.get("source") or "-")),
        ("泄露标题", str(ex.get("title") or "-")),
        ("泄露日期", str(ex.get("breach_date") or "-")),
        ("数据类型", "、".join(str(c) for c in classes) or "-"),
        ("处理建议", str(ex.get("advice") or "-")),
    ]
    total = len(ex.get("accounts") or [])
    if not include_accounts:
        facts.append(("受影响账户", f"{total} 个，请在平台查看"))
    elif total > MAX_LISTED_ACCOUNTS:
        rest = total - MAX_LISTED_ACCOUNTS
        facts.append(
            (
                "受影响账户",
                f"共 {total} 个，下面列出前 {MAX_LISTED_ACCOUNTS} 个，其余 {rest} 个请在平台查看",
            )
        )
    return facts


def _accounts(ex: Mapping[str, Any] | None, include_accounts: bool) -> tuple[str, ...]:
    if ex is None or not include_accounts:
        return ()
    return tuple(str(a) for a in ex.get("accounts") or [])[:MAX_LISTED_ACCOUNTS]


def _masked(
    heading: str | None, facts: list[tuple[str, str]], accounts: tuple[str, ...], link: str
) -> Content:
    return Content(
        heading=mask_text(heading) if heading else None,
        facts=tuple((label, mask_text(value) or "-") for label, value in facts),
        accounts=tuple(mask_text(a) for a in accounts),
        link=link,
    )


def issue_content(
    view: AlertView, extra: Mapping[str, Any] | None, *, include_accounts: bool
) -> Content:
    facts = [
        ("告警编号", str(view.alert_id)),
        ("级别", SEVERITY_LABEL.get(view.severity, view.severity)),
        ("类别", CATEGORY_LABEL.get(view.category, view.category)),
        ("域名 / URL", defang(view.domain)),
        ("评分", str(view.score)),
        ("命中原因", "、".join(view.reasons) or "-"),
        ("首次发现", view.first_seen.isoformat()),
    ]
    ex = _exposure(extra)
    if ex is not None:
        facts += _exposure_facts(ex, include_accounts)
    return _masked(None, facts, _accounts(ex, include_accounts), view.link)


def comment_content(
    view: AlertView, extra: Mapping[str, Any] | None, *, include_accounts: bool
) -> Content:
    """同一告警的后续批次（如新增受影响账户），追加到已有工单。"""
    ex = _exposure(extra)
    count = len(ex.get("accounts") or []) if ex is not None else 0
    heading = f"Open-TI 告警 {view.alert_id}：新增受影响账户 {count} 个"
    facts = _exposure_facts(ex, include_accounts) if ex is not None else []
    return _masked(heading, facts, _accounts(ex, include_accounts), view.link)


def to_text(content: Content) -> str:
    lines = [content.heading] if content.heading else []
    lines += [f"{label}：{value}" for label, value in content.facts]
    if content.accounts:
        lines.append("受影响账户：")
        lines += [f"- {a}" for a in content.accounts]
    lines.append(f"在平台中查看：{content.link}")
    return "\n".join(lines)


def _text(value: str, href: str | None = None) -> dict[str, Any]:
    node: dict[str, Any] = {"type": "text", "text": value}
    if href is not None:
        node["marks"] = [{"type": "link", "attrs": {"href": href}}]
    return node


def _paragraph(*nodes: dict[str, Any]) -> dict[str, Any]:
    return {"type": "paragraph", "content": list(nodes)}


def _bullets(items: list[str]) -> dict[str, Any]:
    return {
        "type": "bulletList",
        "content": [{"type": "listItem", "content": [_paragraph(_text(i))]} for i in items],
    }


def to_adf(content: Content) -> dict[str, Any]:
    """Jira Cloud REST v3 的 Atlassian Document Format。只有平台链接带 link 标记。"""
    blocks: list[dict[str, Any]] = []
    if content.heading:
        blocks.append(_paragraph(_text(content.heading)))
    if content.facts:
        blocks.append(_bullets([f"{label}：{value}" for label, value in content.facts]))
    if content.accounts:
        blocks.append(_paragraph(_text("受影响账户：")))
        blocks.append(_bullets(list(content.accounts)))
    blocks.append(_paragraph(_text("在平台中查看："), _text(content.link, content.link)))
    return {"type": "doc", "version": 1, "content": blocks}
