"""投诉材料（设计文档 12.1）：按投诉对象类型与语言选模板，填入机构信息、仿冒事实与证据摘要。

模板在 config/takedown/templates/<语言>/<类型>.txt，由使用机构维护；第一行为 "Subject: …"。
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from string import Template

from opti.alerting.views import defang
from opti.organization import Organization
from opti.takedown.targets import Target
from opti.takedown.templates import TakedownTemplates

LANGUAGES = ("zh-CN", "en-US")
KINDS = ("registrar", "hosting", "cdn", "report", "platform")
SUBJECT_MAX = 200
CATEGORY_TEXT = {
    "zh-CN": {
        "phishing_site": "钓鱼网站", "typosquat_domain": "仿冒域名", "unapproved_certificate": "未经批准的证书",
        "reported_phishing": "被举报的钓鱼", "clone_site": "克隆网站", "email_spoofing": "冒用邮件发件",
        "impersonation_account": "冒充本机构的账号或主页", "fraud_scam": "冒用本机构名义的诈骗",
    },
    "en-US": {
        "phishing_site": "phishing website", "typosquat_domain": "domain impersonating our brand",
        "unapproved_certificate": "unauthorized certificate", "reported_phishing": "reported phishing",
        "clone_site": "cloned website", "email_spoofing": "email spoofing",
        "impersonation_account": "account impersonating our organization", "fraud_scam": "scam using our organization's name",
    },
}  # fmt: skip
NO_EVIDENCE = {
    "zh-CN": "（暂无截图证据；可在平台中补充取证后重新生成材料）",
    "en-US": "(No screenshot evidence yet.)",
}


class TemplateError(ValueError):
    pass


@dataclass(frozen=True)
class Material:
    subject: str
    body: str


@dataclass(frozen=True)
class EvidenceLine:
    kind: str
    captured_at: datetime
    sha256: str
    source_url: str | None


def defang_url(value: str) -> str:
    return re.sub(
        r"^https?", lambda m: m.group().lower().replace("http", "hxxp"), value, flags=re.IGNORECASE
    ).replace(".", "[.]")


def _line(value: str) -> str:
    """单行字段（会进入主题行）：折叠所有空白与换行。"""
    return " ".join(str(value).split())


def _when(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def build_context(
    org: Organization,
    target: Target,
    *,
    language: str,
    host: str,
    url: str | None,
    category: str,
    first_seen: datetime,
    evidence: Sequence[EvidenceLine],
    ips: Sequence[str],
    now: datetime,
    detail: str = "",
) -> dict[str, str]:
    if language not in LANGUAGES:
        raise TemplateError(f"unsupported language: {language}")
    lines = [
        f"- {e.kind} · {_when(e.captured_at)} · SHA-256 {e.sha256}"
        + (f" · {defang_url(e.source_url)}" if e.source_url else "")
        for e in evidence
    ]
    statement = (
        org.legal_statement_en
        if language == "en-US" and org.legal_statement_en
        else org.legal_statement
    )
    contact = org.takedown_sender or (org.security_contact or "").removeprefix("mailto:") or "-"
    return {
        "org_name": _line(org.name),
        "org_short_name": _line(org.short_name),
        "org_website": org.website or "-",
        "org_contact": contact,
        "legal_statement": statement,
        "signature": org.signature or org.name,
        "target_name": _line(target.name),
        "domain": defang(host),
        "url": defang_url(url) if url else defang(host),
        "ips": ", ".join(ips) or "-",
        "category": CATEGORY_TEXT[language].get(category, category),
        "first_seen": _when(first_seen),
        "evidence": "\n".join(lines) or NO_EVIDENCE[language],
        "detail": detail.strip()[:1000] or "-",
        "date": now.astimezone(UTC).strftime("%Y-%m-%d"),
    }


def render_text(text: str, ctx: Mapping[str, str], *, name: str) -> Material:
    out = Template(text).safe_substitute(ctx)
    first, _, rest = out.partition("\n")
    if not first.startswith("Subject:"):
        raise TemplateError(f"{name} must start with 'Subject:'")
    subject = _line(first.removeprefix("Subject:"))[:SUBJECT_MAX]
    return Material(subject, rest.lstrip("\n").rstrip() + "\n")


def render(
    source: Path | TakedownTemplates, language: str, kind: str, ctx: Mapping[str, str]
) -> Material:
    if language not in LANGUAGES or kind not in KINDS:
        raise TemplateError(f"no template for {language}/{kind}")
    name = f"{language}/{kind}.txt"
    if isinstance(source, Path):
        path = source / language / f"{kind}.txt"
        if not path.is_file():
            raise TemplateError(f"missing template: {name}")
        return render_text(path.read_text(encoding="utf-8"), ctx, name=name)
    return render_text(source.text(language, kind), ctx, name=name)
