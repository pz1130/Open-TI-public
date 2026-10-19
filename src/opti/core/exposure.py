"""凭据暴露载荷（设计文档 4.6）：HIBP 事件目录、按事件分组账户、载荷构造与校验。纯逻辑，不访问网络。

受影响的邮箱只在 accounts 中传递，处理器写入 exposed_account 后不再出现在其他地方（设计文档 2.5）。
"""

from __future__ import annotations

import html
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from opti.core.scoring import ExposureFacts

MAX_ACCOUNTS = 5000
_ALIAS = re.compile(r"^[a-z0-9._%+-]{1,64}$")
_KEY = re.compile(r"^(hibp:[a-z0-9.-]+:[a-zA-Z0-9._-]{1,200}|hudsonrock:[a-z0-9.-]+)$")
KINDS = ("breach", "stealer")
SOURCES = frozenset({"hibp", "hibp_notify", "hudsonrock"})
PUBLIC_CONTEXT = frozenset({"users", "third_parties", "total"})
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


class ExposureError(ValueError):
    pass


@dataclass(frozen=True)
class BreachInfo:
    name: str
    title: str
    breach_date: str | None
    added_date: str | None
    data_classes: tuple[str, ...]
    verified: bool
    fabricated: bool
    sensitive: bool
    spam_list: bool
    stealer_log: bool

    @classmethod
    def unknown(cls, name: str) -> BreachInfo:
        """不在公开目录中的事件（如敏感事件）：按最低可信度处理。"""
        return cls(name, name, None, None, (), False, False, False, False, False)


def _str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def breach_catalog(doc: Any) -> dict[str, BreachInfo]:
    out: dict[str, BreachInfo] = {}
    for b in doc if isinstance(doc, list) else []:
        if not isinstance(b, dict) or not _str(b.get("Name")):
            continue
        name = str(b["Name"])
        if not re.fullmatch(r"[a-zA-Z0-9._-]{1,200}", name):
            continue
        classes = b.get("DataClasses")
        out[name] = BreachInfo(
            name=name,
            title=_EMAIL.sub("[redacted]", _str(b.get("Title")) or name)[:200],
            breach_date=_str(b.get("BreachDate")),
            added_date=_str(b.get("AddedDate")),
            data_classes=tuple(str(c) for c in classes if isinstance(c, str))
            if isinstance(classes, list)
            else (),
            verified=bool(b.get("IsVerified")),
            fabricated=bool(b.get("IsFabricated")),
            sensitive=bool(b.get("IsSensitive")),
            spam_list=bool(b.get("IsSpamList")),
            stealer_log=bool(b.get("IsStealerLog")),
        )
    return out


def group_by_breach(data: Any, domain: str) -> dict[str, list[str]]:
    """HIBP breacheddomain 的结果 {别名: [事件名]} → {事件名: [邮箱]}；非法别名丢弃。"""
    out: dict[str, set[str]] = defaultdict(set)
    for alias, names in data.items() if isinstance(data, Mapping) else []:
        if not isinstance(alias, str) or not isinstance(names, list):
            continue
        a = alias.strip().lower()
        if not _ALIAS.fullmatch(a):
            continue
        for n in names:
            if isinstance(n, str) and re.fullmatch(r"[a-zA-Z0-9._-]{1,200}", n):
                out[n].add(f"{a}@{domain}")
    return {k: sorted(v) for k, v in sorted(out.items())}


def exposure_payload(
    *,
    source: str,
    kind: str,
    key: str,
    domain: str,
    info: BreachInfo | None,
    title: str,
    affected: int,
    accounts: Iterable[str],
    breach_date: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "exposure": {
            "source": source, "kind": kind, "key": key, "domain": domain, "title": title,
            "breach_date": breach_date or (info.breach_date if info else None),
            "added_date": info.added_date if info else None,
            "data_classes": list(info.data_classes) if info else [],
            "verified": info.verified if info else True,
            "fabricated": info.fabricated if info else False,
            "sensitive": info.sensitive if info else False,
            "spam_list": info.spam_list if info else False,
            "stealer_log": info.stealer_log if info else False,
            "affected": int(affected), "accounts": list(accounts), "context": dict(context or {}),
        }
    }  # fmt: skip


def _official(domain: str, official: Iterable[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in (o.lower() for o in official))


def _date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return (
            datetime.fromisoformat(value.replace("Z", "+00:00")).date()
            if "T" in value
            else date.fromisoformat(value)
        )
    except ValueError:
        return None


@dataclass(frozen=True)
class Exposure:
    source: str
    kind: str
    key: str
    domain: str
    title: str
    breach_date: date | None
    added_date: str | None
    data_classes: tuple[str, ...]
    verified: bool
    fabricated: bool
    sensitive: bool
    spam_list: bool
    stealer_log: bool
    affected: int
    accounts: tuple[str, ...]
    context: dict[str, Any]

    def facts(self, now: datetime) -> ExposureFacts:
        age = (now.astimezone(UTC).date() - self.breach_date).days if self.breach_date else None
        return ExposureFacts(
            kind="stealer" if self.kind == "stealer" or self.stealer_log else "breach",
            affected=max(self.affected, len(self.accounts)),
            data_classes=frozenset(self.data_classes),
            age_days=max(age, 0) if age is not None else None,
            verified=self.verified, fabricated=self.fabricated, spam_list=self.spam_list,
        )  # fmt: skip

    def public(self) -> dict[str, Any]:
        """写入 Finding 的部分：只有数量，没有邮箱。"""
        return {
            "source": self.source, "kind": self.kind, "domain": self.domain, "title": self.title,
            "breach_date": self.breach_date.isoformat() if self.breach_date else None,
            "added_date": self.added_date, "data_classes": list(self.data_classes),
            "verified": self.verified, "fabricated": self.fabricated, "sensitive": self.sensitive,
            "spam_list": self.spam_list, "stealer_log": self.stealer_log,
            "affected": max(self.affected, len(self.accounts)), "context": self.context,
        }  # fmt: skip


def parse_exposure(raw: Any, official: Iterable[str]) -> Exposure:
    if not isinstance(raw, Mapping):
        raise ExposureError("exposure 必须是映射")
    domain = str(raw.get("domain") or "").lower().strip(".")
    key, kind = str(raw.get("key") or ""), str(raw.get("kind") or "")
    if not _official(domain, official):
        raise ExposureError(f"{domain} 不是本机构的官方域名")
    if kind not in KINDS or not _KEY.fullmatch(key) or not key.split(":")[1] == domain:
        raise ExposureError("kind 或 key 不合法")
    if (kind == "stealer") != key.startswith("hudsonrock:"):
        raise ExposureError("key 与 kind 不匹配")
    source = str(raw.get("source") or "")
    if source not in SOURCES or (kind == "stealer") != (source == "hudsonrock"):
        raise ExposureError("source 与 kind 不匹配")
    accounts_raw = raw.get("accounts") or []
    if not isinstance(accounts_raw, list) or len(accounts_raw) > MAX_ACCOUNTS:
        raise ExposureError(f"accounts 必须是列表且不超过 {MAX_ACCOUNTS} 个")
    suffix = "@" + domain
    accounts = sorted(
        {
            a.strip().lower()
            for a in accounts_raw
            if isinstance(a, str)
            and a.strip().lower().endswith(suffix)
            and _ALIAS.fullmatch(a.strip().lower()[: -len(suffix)])
        }
    )
    classes = raw.get("data_classes") or []
    context = raw.get("context") or {}
    try:
        affected = max(0, int(raw.get("affected") or 0))
    except (TypeError, ValueError) as e:
        raise ExposureError("affected 不合法") from e
    public_context = (
        {
            k: v
            for k, v in context.items()
            if k in PUBLIC_CONTEXT and isinstance(v, int) and not isinstance(v, bool) and v >= 0
        }
        if isinstance(context, Mapping)
        else {}
    )
    added_date = _str(raw.get("added_date"))
    if added_date and "@" in added_date:
        added_date = None
    return Exposure(
        source=source, kind=kind, key=key, domain=domain,
        title=_EMAIL.sub("[redacted]", str(raw.get("title") or key))[:200], breach_date=_date(raw.get("breach_date")),
        added_date=added_date,
        data_classes=tuple(c[:100] for c in classes if isinstance(c, str) and "@" not in c) if isinstance(classes, list) else (),
        verified=bool(raw.get("verified", True)), fabricated=bool(raw.get("fabricated")),
        sensitive=bool(raw.get("sensitive")), spam_list=bool(raw.get("spam_list")),
        stealer_log=bool(raw.get("stealer_log")), affected=affected,
        accounts=tuple(accounts), context=public_context,
    )  # fmt: skip


def monitored_domains(official: Iterable[str], configured: Iterable[str]) -> list[str]:
    """要监测的邮箱域名：默认官方域名；配置的域名必须是官方域名或其子域。"""
    off = [o.lower().strip(".") for o in official]
    wanted = [str(d).lower().strip(".") for d in configured] or off
    return [d for d in dict.fromkeys(wanted) if _official(d, off)]


MIN_TITLE = 4  # 更短的事件名容易与普通单词混淆
MAX_MATCHES = 3  # 同时提到这么多事件的邮件按新闻简报处理
_TAGS = re.compile(r"<[^>]+>")
_AFFECTED = re.compile(
    r"(\d[\d,]*)\s+(?:of\s+your\s+)?(?:email\s+)?(?:addresses|accounts)\b", re.IGNORECASE
)


@dataclass(frozen=True)
class Notification:
    domain: str
    breaches: tuple[BreachInfo, ...]
    affected: int


def _plain(body: Any) -> str:
    if not isinstance(body, Mapping):
        return ""
    content = str(body.get("content") or "")
    if str(body.get("contentType") or "").lower() == "html":
        content = html.unescape(_TAGS.sub(" ", content))
    return " ".join(content.split())


def _dmarc_pass(msg: Mapping[str, Any], sender_domain: str) -> bool:
    for h in msg.get("internetMessageHeaders") or []:
        if not isinstance(h, Mapping) or str(h.get("name", "")).lower() != "authentication-results":
            continue
        value = str(h.get("value", "")).lower()
        # 只信任收件系统最上方的 Authentication-Results；更下方的同名头可由发件方伪造。
        return bool(
            re.search(r"(?:^|[;\s])dmarc=pass(?:[;\s(]|$)", value)
            and re.search(rf"header\.from={re.escape(sender_domain)}(?:[;\s(]|$)", value)
        )
    return False


def _match_breaches(text: str, catalog: Mapping[str, BreachInfo]) -> list[BreachInfo]:
    found: list[BreachInfo] = []
    for info in sorted(catalog.values(), key=lambda b: -len(b.title)):
        for label in dict.fromkeys((info.title, info.name)):
            if len(label) >= MIN_TITLE and re.search(
                rf"(?<!\w){re.escape(label)}(?!\w)", text, re.IGNORECASE
            ):
                found.append(info)
                break
    return found


def parse_notification(
    msg: Mapping[str, Any],
    *,
    senders: Iterable[str],
    domains: Iterable[str],
    catalog: Mapping[str, BreachInfo],
    require_dmarc: bool = True,
) -> Notification | None:
    """HIBP 域名通知 → 涉及的被监测域名、事件与受影响数量；不确定时返回 None（宁可漏报，不误报）。"""
    sender_entry = msg.get("from")
    address = sender_entry.get("emailAddress") if isinstance(sender_entry, Mapping) else None
    sender = str(address.get("address", "") if isinstance(address, Mapping) else "").lower()
    if sender not in {s.lower() for s in senders}:
        return None
    if require_dmarc and not _dmarc_pass(msg, sender.rsplit("@", 1)[-1]):
        return None
    subject = " ".join(str(msg.get("subject") or "").split())
    body = _plain(msg.get("body"))
    text = f"{subject} {body}"
    domain = next(
        (
            d
            for d in domains
            if re.search(rf"(?<![\w.-]){re.escape(d)}(?![\w-])", text, re.IGNORECASE)
        ),
        None,
    )
    if domain is None:
        return None
    found = _match_breaches(subject, catalog) or _match_breaches(body, catalog)
    if not found or len(found) >= MAX_MATCHES:
        return None
    m = _AFFECTED.search(text)
    affected = int(m.group(1).replace(",", "")) if m else 0
    return Notification(domain, tuple(found), affected)
