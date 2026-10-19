"""CISA 已被利用漏洞目录（KEV，设计文档 4.8）与本机构软件清单的匹配。

软件清单只在平台加载，不下发到采集节点；采集节点只下载公开目录。
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$")
_CWE = re.compile(r"^CWE-\d{1,5}$")
MAX_FIELD = 2000
_WORD = re.compile(r"[^\W_]+")


class KevError(ValueError):
    pass


@dataclass(frozen=True)
class Kev:
    cve: str
    vendor: str
    product: str
    name: str
    description: str
    required_action: str
    date_added: date
    due_date: date | None
    ransomware: bool
    notes: str
    cwes: tuple[str, ...]


def _text(value: Any, limit: int = MAX_FIELD) -> str:
    return " ".join(value.split())[:limit] if isinstance(value, str) else ""


def _date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _cwes(value: Any) -> list[str]:
    return (
        sorted({c for c in value if isinstance(c, str) and _CWE.fullmatch(c)})[:20]
        if isinstance(value, list)
        else []
    )


def kev_payload(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    """把目录中的一条记录整理成载荷；关键字段缺失或格式不对时返回 None。"""
    cve = _text(raw.get("cveID"), 30).upper()
    added = _date(raw.get("dateAdded"))
    vendor, product = _text(raw.get("vendorProject"), 200), _text(raw.get("product"), 200)
    if not CVE.fullmatch(cve) or added is None or not vendor or not product:
        return None
    due = _date(raw.get("dueDate"))
    return {
        "kev": {
            "cve": cve, "vendor": vendor, "product": product, "name": _text(raw.get("vulnerabilityName"), 300),
            "description": _text(raw.get("shortDescription")), "required_action": _text(raw.get("requiredAction")),
            "date_added": added.isoformat(), "due_date": due.isoformat() if due else None,
            "ransomware": _text(raw.get("knownRansomwareCampaignUse"), 20).lower() == "known",
            "notes": _text(raw.get("notes")), "cwes": _cwes(raw.get("cwes")),
        }
    }  # fmt: skip


def digest(payload: Mapping[str, Any]) -> str:
    """条目内容摘要：CISA 修改条目（如勒索利用状态）时摘要随之变化，连接器据此重新回传。"""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()[:16]


def parse_kev(payload: Mapping[str, Any]) -> Kev:
    """平台侧再次校验采集节点送来的载荷。"""
    raw = payload.get("kev")
    if not isinstance(raw, Mapping):
        raise KevError("缺少 kev")
    cve = raw.get("cve")
    added = _date(raw.get("date_added"))
    vendor, product = _text(raw.get("vendor"), 200), _text(raw.get("product"), 200)
    if (
        not isinstance(cve, str)
        or not CVE.fullmatch(cve)
        or added is None
        or not vendor
        or not product
    ):
        raise KevError("kev 字段不完整或格式不对")
    return Kev(
        cve=cve, vendor=vendor, product=product, name=_text(raw.get("name"), 300),
        description=_text(raw.get("description")), required_action=_text(raw.get("required_action")),
        date_added=added, due_date=_date(raw.get("due_date")), ransomware=raw.get("ransomware") is True,
        notes=_text(raw.get("notes")), cwes=tuple(_cwes(raw.get("cwes"))),
    )  # fmt: skip


def normalize_name(value: str) -> str:
    return " ".join(_WORD.findall(unicodedata.normalize("NFKC", value).casefold()))


class Software(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    vendor: str = Field(min_length=1, max_length=200)
    vendor_aliases: tuple[str, ...] = ()
    products: tuple[str, ...] = Field(min_length=1)
    tier: Literal["critical", "high", "normal"] = "normal"
    exposed: bool = False  # 面向互联网
    owner: str = ""

    @field_validator("vendor", "vendor_aliases", "products")
    @classmethod
    def _names_not_empty(cls, v: str | tuple[str, ...]) -> str | tuple[str, ...]:
        if any(not normalize_name(x) for x in ((v,) if isinstance(v, str) else v)):
            raise ValueError(
                "厂商与产品名不能为空；产品要逐个列出（可用 opti kev-products 查看 KEV 中的准确写法）"
            )
        return v


class SoftwareList(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    software: tuple[Software, ...] = ()

    @model_validator(mode="after")
    def _unique_ids(self) -> SoftwareList:
        ids = [s.id for s in self.software]
        if len(ids) != len(set(ids)):
            raise ValueError("软件 id 不能重复")
        return self


def load_software(path: Path) -> SoftwareList:
    if not path.exists():
        return SoftwareList()
    return SoftwareList.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


class SoftwareMatcher:
    def __init__(self, inventory: SoftwareList) -> None:
        self._index: dict[tuple[str, str], list[Software]] = {}
        for s in inventory.software:
            for vendor in (s.vendor, *s.vendor_aliases):
                for product in s.products:
                    self._index.setdefault(
                        (normalize_name(vendor), normalize_name(product)), []
                    ).append(s)

    @property
    def empty(self) -> bool:
        return not self._index

    def match(self, vendor: str, product: str) -> list[Software]:
        hits = self._index.get((normalize_name(vendor), normalize_name(product)), [])
        return list({s.id: s for s in hits}.values())
