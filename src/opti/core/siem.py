"""SIEM 事件格式（设计文档 12）：CEF、RFC 5424 Syslog 帧、JSON 与 Splunk HEC。

给机器用：指标不去链接化。CEF 头部转义反斜杠与竖线，扩展字段转义反斜杠、等号与换行，
防止一条事件被拆开或被伪造出额外字段。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

CEF_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
FACILITY_LOCAL0 = 16
MAX_MSG = 1000
NO_OBSERVABLES = frozenset({"unapproved_certificate"})  # 针对本机构自己的域名：不能让 SIEM 拿去阻断
_NOT_PRINTABLE = re.compile(r"[^!-~]")


@dataclass(frozen=True)
class SiemEvent:
    alert_id: int
    project_id: str
    severity: str
    category: str
    score: int
    reasons: tuple[str, ...]
    entity_type: str
    entity_value: str
    title: str  # 给人看的主题：文本类为标题，漏洞为 CVE 编号与名称，其余同实体值
    created_at: datetime
    link: str

    def observables(self) -> dict[str, str]:
        if self.category in NO_OBSERVABLES:
            return {}
        if self.entity_type == "domain":
            return {"domain": self.entity_value}
        if self.entity_type == "url":
            host = urlsplit(self.entity_value).hostname
            return {"url": self.entity_value, **({"domain": host} if host else {})}
        if self.entity_type == "ip":
            return {"ip": self.entity_value}
        if self.entity_type == "cve":
            return {"cve": self.entity_value}
        return {}

    def to_json(self) -> dict[str, Any]:
        return {
            "event": "alert.opened", "id": f"opti-alert-{self.alert_id}", "alert_id": self.alert_id,
            "project_id": self.project_id, "severity": self.severity, "category": self.category,
            "score": self.score, "reasons": list(self.reasons), "title": self.title,
            "observables": self.observables(), "created_at": self.created_at.astimezone(UTC).isoformat(),
            "link": self.link,
        }  # fmt: skip


def _header(value: str) -> str:
    return " ".join(value.replace("\\", "\\\\").replace("|", "\\|").split())


def _ext(value: str) -> str:
    v = value.replace("\\", "\\\\").replace("=", "\\=")
    return v.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")


def cef(event: SiemEvent, *, version: str) -> str:
    ext: dict[str, str] = {
        "rt": str(int(event.created_at.timestamp() * 1000)), "externalId": str(event.alert_id),
        "cat": event.category, "cn1Label": "score", "cn1": str(event.score), "cs1Label": "reasons",
        "cs1": ",".join(event.reasons), "cs2Label": "link", "cs2": event.link, "cs3Label": "project",
        "cs3": event.project_id, "msg": event.title[:MAX_MSG],
    }  # fmt: skip
    obs = event.observables()
    if "domain" in obs:
        ext["dhost"] = obs["domain"]
    if "url" in obs:
        ext["request"] = obs["url"]
    if "ip" in obs:
        try:
            ip = ipaddress.ip_address(obs["ip"])
        except ValueError:
            ip = None
        if ip is not None and ip.version == 4:
            ext["dst"] = str(ip)
        elif ip is not None:
            ext["c6a2Label"], ext["c6a2"] = "ip", str(ip)
    header = [
        "CEF:0", "Open-TI", "Open-TI", _header(version), _header(event.category),
        _header(f"Open-TI {event.category} alert"), str(CEF_SEVERITY.get(event.severity, 5)),
    ]  # fmt: skip
    return "|".join(header) + "|" + " ".join(f"{k}={_ext(v)}" for k, v in ext.items())


def syslog_frame(
    message: str, *, severity: str, hostname: str, app_name: str, now: datetime
) -> bytes:
    """RFC 5424：<PRI>1 时间 主机 应用 - MSGID - 消息（设施 local0）。"""
    pri = FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY.get(severity, 5)
    ts = now.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = _NOT_PRINTABLE.sub("", hostname)[:255] or "-"
    return f"<{pri}>1 {ts} {host} {app_name} - opti-alert - {message}".encode()


def octet_framed(frame: bytes) -> bytes:
    """RFC 6587 八位组计数分帧（TCP / TLS）：消息中出现换行也不会被拆开。"""
    return f"{len(frame)} ".encode() + frame


def hec_payload(event: SiemEvent) -> dict[str, Any]:
    return {
        "time": event.created_at.timestamp(), "host": "open-ti", "source": "open-ti",
        "sourcetype": "opti:alert", "event": event.to_json(),
    }  # fmt: skip
