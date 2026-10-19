"""投诉对象清单（设计文档 12.1）：注册商、CDN、托管商与并行举报渠道。只读缓存的富化结果。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from opti.core.domains import to_ascii
from opti.takedown.config import Channel, TakedownConfig
from opti.takedown.hosting import HostData, ip_literal

# 单个地址：不允许空白、逗号、尖括号——这些会被邮件客户端解析成多个收件人或额外的邮件头
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}$")
_SLUG = re.compile(r"[^a-z0-9]+")
_ORDER = {"registrar": 0, "cdn": 1, "hosting": 2, "report": 3, "platform": 4}


@dataclass(frozen=True)
class Target:
    kind: str  # registrar / hosting / cdn / report / platform
    id: str
    name: str
    email: str | None
    url: str | None
    basis: str  # rdap_registrar / nameserver / ip_network / ip_rdap / reporting / escalation
    detail: str = ""  # 依据的具体值：名称服务器、IP
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Target:
        return cls(
            kind=str(d["kind"]), id=str(d["id"]), name=str(d["name"]),
            email=d.get("email") or None, url=d.get("url") or None, basis=str(d.get("basis") or ""),
            detail=str(d.get("detail") or ""), note=str(d.get("note") or ""),
        )  # fmt: skip


@dataclass(frozen=True)
class TargetList:
    host: str
    targets: list[Target]
    missing_hosting: list[str]  # 还没有 RDAP 结果的托管 IP（worker 稍后会查）

    def get(self, target_id: str) -> Target | None:
        return next((t for t in self.targets if t.id == target_id), None)


def clean_email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().removeprefix("mailto:")
    return v if _EMAIL.fullmatch(v) else None


def slug(value: str) -> str:
    return _SLUG.sub("-", value.casefold()).strip("-")[:60] or "unknown"


def _contact(c: Channel) -> tuple[str | None, str | None]:
    return clean_email(c.email), c.url


def _tld(host: str) -> str | None:
    if ip_literal(host) is not None:
        return None
    return to_ascii(host).rstrip(".").rsplit(".", 1)[-1].lower()


def discover(cfg: TakedownConfig, data: HostData) -> TargetList:
    platform = cfg.platform_for(data.host)
    if platform is not None:
        email, url = _contact(platform.channel) if platform.channel else (None, None)
        target = Target(
            "platform", f"platform:{platform.id}", platform.name, email, url,
            basis="platform", note=platform.note,
        )  # fmt: skip
        return TargetList(data.host, [target], [])
    found: dict[str, Target] = {}

    def add(t: Target) -> None:
        found.setdefault(t.id, t)

    rdap = data.rdap or {}
    abuse = clean_email(rdap.get("abuse_email"))
    if rdap.get("registrar") or abuse:
        name = str(rdap.get("registrar") or "Registrar")
        add(Target("registrar", f"registrar:{slug(name)}", name, abuse, None, "rdap_registrar"))

    nameservers = [str(n).lower().rstrip(".") for n in rdap.get("nameservers") or []]
    for p in cfg.providers:
        suffixes = [s.lower().lstrip("*") for s in p.nameservers]
        hit = next((ns for ns in nameservers if any(ns.endswith(sfx) for sfx in suffixes)), None)
        if hit is not None:
            add(Target("cdn", f"cdn:{p.id}", p.name, *_contact(p.channel), basis="nameserver", detail=hit, note=p.note))  # fmt: skip

    missing: list[str] = []
    for ip, info in data.ips.items():
        if info is None:
            missing.append(ip)
            continue
        if info.get("found") is not True:
            continue
        network = str(info.get("network_name") or "")
        org = str(info.get("org") or "")
        provider = next(
            (
                p for p in cfg.providers
                if any(network.upper().startswith(n.upper()) for n in p.network_names)
                or any(o.casefold() in org.casefold() for o in p.orgs)
            ),
            None,
        )  # fmt: skip
        if provider is not None:
            add(Target("cdn", f"cdn:{provider.id}", provider.name, *_contact(provider.channel), basis="ip_network", detail=ip, note=provider.note))  # fmt: skip
            continue
        handle = str(info.get("handle") or network or ip)
        add(Target("hosting", f"hosting:{slug(handle)}", org or network or ip, clean_email(info.get("abuse_email")), None, basis="ip_rdap", detail=ip))  # fmt: skip

    tld = _tld(data.host)
    for rc in cfg.reporting:
        if rc.tlds and (tld is None or tld not in {t.lower() for t in rc.tlds}):
            continue
        add(Target("report", f"report:{rc.id}", rc.name, *_contact(rc.channel), basis="reporting", note=rc.note))  # fmt: skip

    ordered = sorted(found.values(), key=lambda t: _ORDER[t.kind])  # 稳定排序：同类保持发现顺序
    return TargetList(data.host, ordered, missing)


def escalations(cfg: TakedownConfig, kind: str) -> list[Target]:
    return [
        Target(e.kind, f"escalation:{slug(e.name)}", e.name, *_contact(e.channel), basis="escalation", note=e.note)
        for e in cfg.escalation
        if e.kind == kind
    ]  # fmt: skip
