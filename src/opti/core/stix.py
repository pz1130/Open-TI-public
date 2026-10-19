"""STIX 2.1 映射（设计文档 6.4）：把整理好的发现转成 STIX 对象，供 OpenCTI / MISP / SIEM 导入。

纯逻辑。ID 由项目与实体确定性生成，重复导出时下游可去重。只导出指标、标题、来源链接与统计：
不导出命中上下文、员工邮箱、软件清单等个人或内部信息。
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import stix2
from stix2 import v21

from opti.core.attack import candidate_tags, catalog
from opti.core.secret_guard import mask_deep

NAMESPACE = uuid.UUID("5d3f9c1e-7b2a-5e44-9c61-2f0a8b7d4e13")
TLP: dict[str, Any] = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}
INDICATOR_CATEGORIES = frozenset(
    {"phishing_site", "typosquat_domain", "reported_phishing", "clone_site", "email_spoofing"}
)  # 未经批准的证书针对的是本机构自己的域名，不能作为指标（下游会拉黑自己）
MALICIOUS = frozenset({"phishing_site", "reported_phishing", "clone_site"})
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)  # 固定对象的创建时间：重复导出时内容一致


@dataclass(frozen=True)
class StixEvidence:
    evidence_id: int
    content_type: str
    sha256: str


@dataclass(frozen=True)
class StixFinding:
    finding_id: int
    category: str
    severity: str
    score: int
    entity_type: str
    entity_value: str
    first_seen: datetime
    last_seen: datetime
    observations: int
    confirmed: bool  # 最近一次研判为真实威胁
    match: Mapping[str, Any] = field(default_factory=dict)
    evidence: tuple[StixEvidence, ...] = ()


def _id(kind: str, scope: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{scope}|{kind}|{key}')}"


def _quote(value: str) -> str:
    """STIX 模式中的字符串常量：转义反斜杠与单引号。"""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _dict(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class _Builder:
    def __init__(self, *, project: str, organization: str, base_url: str, tlp: str) -> None:
        self.project, self.base_url = project, base_url.rstrip("/")
        self.marking = TLP[tlp]
        marks = [self.marking.id]
        self.platform = v21.Identity(
            id=_id("identity", project, "platform"), name="Open-TI", identity_class="system",
            created=EPOCH, modified=EPOCH, object_marking_refs=marks,
        )  # fmt: skip
        self.org = v21.Identity(
            id=_id("identity", project, "organization"), name=organization, identity_class="organization",
            created=EPOCH, modified=EPOCH, created_by_ref=self.platform.id, object_marking_refs=marks,
        )  # fmt: skip
        self.objects: dict[str, Any] = {}
        for o in (self.marking, self.platform, self.org):
            self._add(o)

    def _add(self, obj: Any) -> Any:
        return self.objects.setdefault(obj.id, obj)

    def _common(self, f: StixFinding) -> dict[str, Any]:
        return {
            "created_by_ref": self.platform.id, "object_marking_refs": [self.marking.id],
            "created": f.first_seen, "modified": max(f.first_seen, f.last_seen),
        }  # fmt: skip

    def _rel(self, source: str, kind: str, target: str, f: StixFinding) -> None:
        self._add(
            v21.Relationship(
                id=_id("relationship", self.project, f"{source}|{kind}|{target}"),
                source_ref=source, relationship_type=kind, target_ref=target, **self._common(f),
            )
        )  # fmt: skip

    def _attack(self, tid: str) -> Any:
        technique = catalog()[tid]
        return self._add(
            v21.AttackPattern(
                id=_id("attack-pattern", "global", tid), name=str(technique["name"]), created=EPOCH, modified=EPOCH,
                external_references=[{"source_name": "mitre-attack", "external_id": tid, "url": technique["url"]}],
            )
        )  # fmt: skip

    def _observable(self, f: StixFinding) -> tuple[Any, str] | None:
        marks = [self.marking.id]
        if f.entity_type == "domain":
            return v21.DomainName(value=f.entity_value, object_marking_refs=marks), "domain-name"
        if f.entity_type == "url":
            return v21.URL(value=f.entity_value, object_marking_refs=marks), "url"
        if f.entity_type == "ip":
            try:
                ip = ipaddress.ip_address(f.entity_value)
            except ValueError:
                return None
            cls, kind = (
                (v21.IPv4Address, "ipv4-addr")
                if ip.version == 4
                else (v21.IPv6Address, "ipv6-addr")
            )
            return cls(value=str(ip), object_marking_refs=marks), kind
        return None

    def add(self, f: StixFinding) -> None:
        obs = self._observable(f) if f.category in INDICATOR_CATEGORIES else None
        if obs is not None:
            self._indicator(f, *obs)
        elif f.category == "ransomware_mention":
            self._ransomware(f)
        elif f.category == "vulnerability":
            self._vulnerability(f)
        else:
            self._report(f, [self.org.id])

    def _indicator(self, f: StixFinding, sco: Any, kind: str) -> None:
        self._add(sco)
        reasons = [
            str(r.get("reason")) for r in f.match.get("reasons") or [] if isinstance(r, Mapping)
        ]
        malicious = f.confirmed or f.category in MALICIOUS
        extra = {"description": ", ".join(reasons)} if reasons else {}
        indicator = self._add(
            v21.Indicator(
                id=_id("indicator", self.project, f"{f.entity_type}:{f.entity_value}"), name=f.entity_value,
                pattern=f"[{kind}:value = '{_quote(str(sco.value))}']", pattern_type="stix", valid_from=f.first_seen,
                indicator_types=["malicious-activity" if malicious else "anomalous-activity"],
                confidence=max(0, min(100, f.score)), labels=[f.category], **extra, **self._common(f),
            )
        )  # fmt: skip
        self._rel(indicator.id, "based-on", sco.id, f)
        # 类别映射仅提供候选 ATT&CK 上下文；不使用 indicates 宣称已观察到该技术。
        for tag in candidate_tags(f.category):
            self._rel(indicator.id, "related-to", self._attack(tag["id"]).id, f)
        self._add(
            v21.Sighting(
                id=_id("sighting", self.project, str(f.finding_id)), sighting_of_ref=indicator.id,
                first_seen=f.first_seen, last_seen=max(f.first_seen, f.last_seen),
                count=max(1, min(f.observations, 999_999_999)), where_sighted_refs=[self.platform.id],
                **self._common(f),
            )
        )  # fmt: skip
        for ev in f.evidence:
            artifact = self._add(
                v21.Artifact(
                    mime_type=ev.content_type, url=f"{self.base_url}/api/v1/evidence/{ev.evidence_id}/content",
                    hashes={"SHA-256": ev.sha256}, object_marking_refs=[self.marking.id],
                )
            )  # fmt: skip
            self._rel(indicator.id, "related-to", artifact.id, f)

    def _report(self, f: StixFinding, refs: list[str], name: str | None = None) -> None:
        doc = _dict(f.match.get("document"))
        title = str(doc.get("title") or "").strip()
        extra: dict[str, Any] = {}
        url = doc.get("url")
        if isinstance(url, str) and url.startswith(("https://", "http://")):
            extra["external_references"] = [
                {"source_name": str(doc.get("source_name") or "source")[:200], "url": url}
            ]
        self._add(
            v21.Report(
                id=_id("report", self.project, str(f.finding_id)),
                name=(name or title or f"{f.category}: {f.entity_value}")[:300], published=f.first_seen,
                report_types=["threat-report"], object_refs=refs, labels=[f.category],
                confidence=max(0, min(100, f.score)), **extra, **self._common(f),
            )
        )  # fmt: skip

    def _ransomware(self, f: StixFinding) -> None:
        post = _dict(f.match.get("post"))
        group = str(post.get("group") or "unknown")[:200]
        victim_name = str(post.get("victim") or f.entity_value)[:200]
        actor = self._add(
            v21.ThreatActor(
                id=_id("threat-actor", "global", group.casefold()), name=group, threat_actor_types=["crime-syndicate"],
                created=EPOCH, modified=EPOCH, created_by_ref=self.platform.id, object_marking_refs=[self.marking.id],
            )
        )  # fmt: skip
        victim = self._add(
            v21.Identity(
                id=_id("identity", self.project, f"victim|{victim_name.casefold()}"), name=victim_name,
                identity_class="organization", **self._common(f),
            )
        )  # fmt: skip
        self._rel(actor.id, "targets", victim.id, f)
        self._report(
            f,
            [self.org.id, actor.id, victim.id],
            name=f"Ransomware leak-site post: {victim_name} ({group})",
        )

    def _vulnerability(self, f: StixFinding) -> None:
        kev = _dict(f.match.get("kev"))
        cve = str(kev.get("cve") or f.entity_value)[:50]
        vuln = self._add(
            v21.Vulnerability(
                id=_id("vulnerability", "global", cve), name=cve, labels=["known-exploited"],
                external_references=[{"source_name": "cve", "external_id": cve}], created=EPOCH, modified=EPOCH,
                created_by_ref=self.platform.id, object_marking_refs=[self.marking.id],
            )
        )  # fmt: skip
        self._report(
            f, [self.org.id, vuln.id], name=f"Known exploited vulnerability relevant to us: {cve}"
        )

    def bundle(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(
            v21.Bundle(objects=list(self.objects.values())).serialize()
        )
        return data


def build_bundle(
    findings: Iterable[StixFinding],
    *,
    project: str,
    organization: str,
    base_url: str,
    tlp: str = "amber",
) -> dict[str, Any]:
    builder = _Builder(project=project, organization=organization, base_url=base_url, tlp=tlp)
    for f in findings:
        builder.add(f)
    masked: dict[str, Any] = mask_deep(builder.bundle())
    return masked
