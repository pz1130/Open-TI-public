"""域名解析与同形字骨架（设计文档 7.3）。"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

import tldextract

# 常见可混淆字符 → 拉丁字母（UTS #39 confusables 的精简子集，覆盖仿冒域名中最常见的西里尔/希腊字母）
_CONFUSABLES = str.maketrans(
    {
        # 西里尔字母
        "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ь": "b", "һ": "h", "ӏ": "l",
        "ԛ": "q", "ԝ": "w", "к": "k", "м": "m",
        # 希腊字母
        "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
        "χ": "x", "ε": "e", "η": "n",
        # 其他拉丁变体
        "ɡ": "g", "ı": "i", "ȷ": "j", "ł": "l", "đ": "d", "ð": "d", "ø": "o", "ɑ": "a",
        "ɩ": "i",
    }
)  # fmt: skip
_BAD_LABEL_CHARS = re.compile(r"[\s/\\@:*]")


def skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKC", label).casefold().translate(_CONFUSABLES)
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def _decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode").casefold()
        except (UnicodeError, ValueError):
            return label
    return label


def normalize_domain(raw: str) -> str | None:
    s = raw.strip().casefold().rstrip(".")
    while s.startswith("*."):
        s = s[2:]
    if not s or len(s) > 253:
        return None
    labels = [_decode_label(x) for x in s.split(".")]
    if len(labels) < 2:
        return None
    if any(not x or len(x) > 63 or _BAD_LABEL_CHARS.search(x) for x in labels):
        return None
    if all(x.isdigit() for x in labels):
        return None  # IPv4 地址
    return ".".join(labels)


def to_ascii(domain: str) -> str:
    """把 Unicode 标签编码为 Punycode（xn--）；用于 DNS 查询、RDAP、Tranco 等只接受 ASCII 的场景。"""
    return ".".join(
        label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
        for label in domain.split(".")
    )


@dataclass(frozen=True)
class DomainParts:
    fqdn: str  # 规范化后的完整主机名（Unicode）
    registered: str  # 可注册域（eTLD+1），如 secure-login.xyz
    label: str  # 可注册域的主体标签，如 secure-login
    suffix: str  # 公共后缀，如 xyz、com.cn
    subdomain_labels: tuple[str, ...]


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # 只用随包附带的公共后缀列表快照，不联网，结果可复现；
    # 包含 github.io 等私有后缀，使 brand-loans.github.io 被视为独立的可注册域
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


def parse_domain(raw: str) -> DomainParts | None:
    fqdn = normalize_domain(raw)
    if fqdn is None:
        return None
    r = _extractor()(fqdn)
    if r.suffix and r.domain:
        sub = tuple(x for x in r.subdomain.split(".") if x)
        label, suffix = r.domain, r.suffix
    else:
        # 快照中没有的新顶级域：把最后一个标签当作后缀
        parts = fqdn.split(".")
        label, suffix, sub = parts[-2], parts[-1], tuple(parts[:-2])
    return DomainParts(
        fqdn=fqdn,
        registered=f"{label}.{suffix}",
        label=label,
        suffix=suffix,
        subdomain_labels=sub,
    )
