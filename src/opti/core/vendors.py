"""Exact organization and vendor matching for ransomware victim names."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from opti.core.domains import normalize_domain, parse_domain
from opti.organization import Organization

LEGAL_SUFFIXES = frozenset(
    {
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "co",
        "company",
        "ltd",
        "limited",
        "llc",
        "llp",
        "plc",
        "gmbh",
        "ag",
        "sa",
        "sas",
        "spa",
        "srl",
        "bv",
        "nv",
        "oy",
        "ab",
        "pty",
        "pte",
        "kk",
        "sl",
        "sarl",
        "group",
        "holding",
        "holdings",
    }
)
CJK_SUFFIXES = ("股份有限公司", "有限责任公司", "有限公司", "集团")
MIN_NAME = 3
_TOKEN = re.compile(r"[^\W_]+")
_HOST = re.compile(r"^[^\s/:@]+\.[^\s/:@]+$")


def normalize_org(name: str) -> str:
    s = (
        unicodedata.normalize("NFKC", name)
        .casefold()
        .strip()
        .replace("&", " and ")
        .replace(".", "")
    )
    for suffix in CJK_SUFFIXES:
        if s.endswith(suffix) and len(s) > len(suffix):
            s = s[: -len(suffix)]
            break
    tokens = _TOKEN.findall(s)
    while len(tokens) > 1 and tokens[-1] in LEGAL_SUFFIXES:
        tokens.pop()
    return " ".join(tokens)


def host_key(value: str) -> str | None:
    v = value.strip()
    if not _HOST.fullmatch(v):
        return None
    host = normalize_domain(v)
    if host is None:
        return None
    parts = parse_domain(host)
    return parts.registered if parts is not None else ".".join(host.split(".")[-2:])


class Vendor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    name: str = Field(min_length=1, max_length=200)
    aliases: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    tier: Literal["critical", "high", "normal"] = "normal"
    owner: str = ""


class VendorList(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    vendors: tuple[Vendor, ...] = ()

    @model_validator(mode="after")
    def _unique_ids(self) -> VendorList:
        ids = [v.id for v in self.vendors]
        if len(ids) != len(set(ids)):
            raise ValueError("供应商 id 不能重复")
        return self


def load_vendors(path: Path) -> VendorList:
    if not path.exists():
        return VendorList()
    return VendorList.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


@dataclass(frozen=True)
class Party:
    kind: str
    id: str
    name: str
    tier: str
    owner: str


@dataclass(frozen=True)
class PartyMatch:
    party: Party
    how: str
    detail: str


class PartyMatcher:
    def __init__(self, org: Organization, official: Iterable[str], vendors: VendorList) -> None:
        self._names: dict[str, Party] = {}
        self._domains: dict[str, Party] = {}
        me = Party("self", "self", org.name, "critical", "")
        if org.name != Organization().name:
            for name in (org.name, org.short_name):
                self._add_name(name, me)
        for d in official:
            self._add_domain(d, me)
        for v in vendors.vendors:
            party = Party("vendor", v.id, v.name, v.tier, v.owner)
            for name in (v.name, *v.aliases):
                self._add_name(name, party)
            for d in v.domains:
                self._add_domain(d, party)

    def _add_name(self, name: str, party: Party) -> None:
        key = normalize_org(name)
        if len(key) >= MIN_NAME:
            self._names.setdefault(key, party)

    def _add_domain(self, domain: str, party: Party) -> None:
        key = host_key(domain)
        if key:
            self._domains.setdefault(key, party)

    @property
    def empty(self) -> bool:
        return not (self._names or self._domains)

    def match(self, victim: str, domain: str | None) -> list[PartyMatch]:
        found: dict[str, PartyMatch] = {}
        for candidate in (domain, victim):
            key = host_key(candidate) if candidate else None
            if key and key in self._domains:
                p = self._domains[key]
                found.setdefault(f"{p.kind}:{p.id}", PartyMatch(p, "domain", key))
        name = normalize_org(victim)
        if name in self._names:
            p = self._names[name]
            found.setdefault(f"{p.kind}:{p.id}", PartyMatch(p, "name", name))
        return list(found.values())


def ransomware_reasons(matches: Iterable[PartyMatch]) -> list[str]:
    reasons: list[str] = []
    for m in matches:
        if m.party.kind == "self":
            reasons.append("own_organization")
        else:
            reasons.append(
                {"critical": "critical_vendor", "high": "high_vendor"}.get(m.party.tier, "vendor")
            )
        if m.how == "domain":
            reasons.append("matched_by_domain")
    return list(dict.fromkeys(reasons))
