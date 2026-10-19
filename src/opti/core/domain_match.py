"""仿冒域名匹配（设计文档 7.3）：判断一个主机名是否在仿冒受保护品牌。"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Literal

from rapidfuzz.distance import Levenshtein

from opti.core.config import DomainRules
from opti.core.domains import DomainParts, normalize_domain, parse_domain, skeleton

Where = Literal["registered", "subdomain"]
Status = Literal["official", "known_lookalike", "match"]


class Reason(StrEnum):
    OFFICIAL_EMBEDDED = (
        "official_embedded"  # 官方域名形态：example.org.x.xyz、example-org.com、exampleorg.org
    )
    BRAND_LABEL = "brand_label"  # 标签或连字符分段与品牌词完全相同：brand-portal.top
    BRAND_COMBO = "brand_combo"  # 品牌词与词缀无分隔拼接：brandloans.com、loginbrand.net
    BRAND_SUBSTRING = "brand_substring"  # 长品牌词出现在标签中：examplebrandhr.org
    BRAND_FUZZY = "brand_fuzzy"  # 长品牌词的拼写变体：examplebramd.com
    HOMOGLYPH = "homoglyph"  # 只有映射同形字后才匹配：branԁ-loans.com
    FRAUD_AFFIX = "fraud_affix"  # 含诈骗相关词缀：loan、grant、pay、login…


# 只作为附加信号、不能单独构成命中的原因
_AUXILIARY = frozenset({Reason.HOMOGLYPH, Reason.FRAUD_AFFIX})


@dataclass(frozen=True)
class MatchReason:
    reason: Reason
    token: str
    label: str
    where: Where
    detail: str = ""


@dataclass(frozen=True)
class DomainMatch:
    domain: str
    registered: str
    status: Status
    reasons: tuple[MatchReason, ...] = ()

    @property
    def subdomain_only(self) -> bool:
        # 子域伪装官方域名（example.org.secure-login.xyz）是典型攻击手法，不算"仅子域命中"
        if self.has(Reason.OFFICIAL_EMBEDDED):
            return False
        primary = [r for r in self.reasons if r.reason not in _AUXILIARY]
        return bool(primary) and all(r.where == "subdomain" for r in primary)

    def has(self, reason: Reason) -> bool:
        return any(r.reason == reason for r in self.reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "registered": self.registered,
            "status": self.status,
            "reasons": [asdict(r) for r in self.reasons],
        }


def _fuzzy_budget(token: str) -> int:
    return 1 if len(token) < 10 else 2


def _min_window_distance(text: str, token: str) -> int:
    """token 与 text 中任一长度相近的子串之间的最小编辑距离。"""
    n = len(token)
    if len(text) <= n + 1:
        return int(Levenshtein.distance(text, token))
    best = n
    for w in (n - 1, n, n + 1):
        for i in range(len(text) - w + 1):
            best = min(best, int(Levenshtein.distance(text[i : i + w], token, score_cutoff=best)))
            if best == 0:
                return 0
    return best


def _combo_rest(seg: str, token: str) -> str | None:
    if seg.startswith(token):
        return seg[len(token) :]
    if seg.endswith(token):
        return seg[: -len(token)]
    return None


def _split_pieces(token: str, n: int) -> list[str]:
    """把 token 切成 n 段连续子串。编辑距离 ≤ n-1 时至少有一段原样保留（鸽巢原理）。"""
    size, extra = divmod(len(token), n)
    pieces, i = [], 0
    for k in range(n):
        step = size + (1 if k < extra else 0)
        pieces.append(token[i : i + step])
        i += step
    return [p for p in pieces if p]


class DomainMatcher:
    def __init__(self, rules: DomainRules) -> None:
        self._official = frozenset(rules.official)
        self._lookalikes = frozenset(rules.known_lookalikes)
        tokens = {t.replace("-", "") for t in rules.brand_tokens}
        tokens.discard("")
        self._short = tuple(sorted(t for t in tokens if len(t) <= rules.short_token_max_len))
        self._long = tuple(sorted(t for t in tokens if len(t) > rules.short_token_max_len))
        self._affixes = frozenset(a for a in (*rules.combo_affixes, *rules.fraud_affixes) if a)
        self._fraud = tuple(sorted((a for a in rules.fraud_affixes if a), key=len, reverse=True))
        self._official_labels = tuple(tuple(d.split(".")) for d in rules.official)
        self._restricted = {
            t.replace("-", ""): frozenset(value.replace("-", "") for value in a)
            for t, a in rules.restricted_tokens.items()
            if t.replace("-", "")
        }
        # 预过滤子串：短品牌词、长品牌词的鸽巢分段、官方域名与合法相似方的首个标签
        patterns: set[str] = set(self._short) | set(self._restricted)
        for t in self._long:
            patterns.update(_split_pieces(t, _fuzzy_budget(t) + 1))
        for d in (*rules.official, *rules.known_lookalikes):
            first = d.split(".")[0]
            if len(first) >= 2:
                patterns.add(first)
        self._prefilter = tuple(sorted(patterns))

    def could_match(self, raw: str) -> bool:
        """廉价预过滤（设计文档 7.3）：用于 CT 流、新注册域名列表等大批量输入。

        保证不漏报：凡 match() 返回非 None 的域名，本方法一定返回 True。
        """
        s = raw.casefold()
        if "xn--" in s or not s.isascii():
            s = skeleton(normalize_domain(raw) or s)
        s = s.replace("-", "")
        return any(p in s for p in self._prefilter)

    def match(self, raw: str) -> DomainMatch | None:
        parts = parse_domain(raw)
        if parts is None:
            return None
        if parts.registered in self._official:
            return DomainMatch(parts.fqdn, parts.registered, "official")
        if parts.registered in self._lookalikes:
            return DomainMatch(parts.fqdn, parts.registered, "known_lookalike")

        reasons = self._embedded(parts)
        for label, where in self._labels(parts):
            reasons.extend(self._label_reasons(label, where))
        if not any(r.reason not in _AUXILIARY for r in reasons):
            return None
        return DomainMatch(parts.fqdn, parts.registered, "match", tuple(dict.fromkeys(reasons)))

    @staticmethod
    def _labels(parts: DomainParts) -> Iterable[tuple[str, Where]]:
        yield parts.label, "registered"
        for s in parts.subdomain_labels:
            yield s, "subdomain"

    def _is_affix(self, rest: str) -> bool:
        return rest in self._affixes or (rest.isdigit() and len(rest) <= 4)

    def _embedded(self, parts: DomainParts) -> list[MatchReason]:
        out: list[MatchReason] = []
        # 子域伪装：example.org.secure-login.xyz（最后一个元素是可注册域的主体标签）
        seq = [skeleton(x) for x in (*parts.subdomain_labels, parts.label)]
        for off in self._official_labels:
            n = len(off)
            for i in range(len(seq) - n + 1):
                if tuple(seq[i : i + n]) == off:
                    where: Where = "registered" if i + n == len(seq) else "subdomain"
                    out.append(
                        MatchReason(Reason.OFFICIAL_EMBEDDED, ".".join(off), ".".join(off), where)
                    )
        # 扁平形态：example-org.com、exampleorg.org、example-org-login.com
        for label, where in self._labels(parts):
            segs = [s for s in skeleton(label).split("-") if s]
            for off in self._official_labels:
                n = len(off)
                windows = (tuple(segs[i : i + n]) for i in range(len(segs) - n + 1))
                if any(w == off for w in windows) or "".join(off) in segs:
                    out.append(MatchReason(Reason.OFFICIAL_EMBEDDED, ".".join(off), label, where))
        return out

    def _label_reasons(self, label: str, where: Where) -> list[MatchReason]:
        sk = skeleton(label)
        segs = [s for s in sk.split("-") if s]
        flat = "".join(segs)
        out: list[MatchReason] = []
        matched: list[str] = []

        for t in self._short:
            if t in segs:
                out.append(MatchReason(Reason.BRAND_LABEL, t, label, where))
                matched.append(t)
                continue
            for seg in segs:
                rest = _combo_rest(seg, t)
                if rest and self._is_affix(rest):
                    out.append(MatchReason(Reason.BRAND_COMBO, t, label, where, detail=rest))
                    matched.append(t)
                    break

        for t, affixes in self._restricted.items():
            if t in segs:
                affix = next((s for s in segs if s in affixes), None)
            else:
                rests = (_combo_rest(seg, t) for seg in segs)
                affix = next((r for r in rests if r and r in affixes), None)
            if affix is not None:
                out.append(MatchReason(Reason.BRAND_COMBO, t, label, where, detail=affix))
                matched.append(t)

        for t in self._long:
            if flat == t:
                out.append(MatchReason(Reason.BRAND_LABEL, t, label, where))
                matched.append(t)
            elif t in flat:
                out.append(MatchReason(Reason.BRAND_SUBSTRING, t, label, where))
                matched.append(t)
            else:
                d = _min_window_distance(flat, t)
                if d <= _fuzzy_budget(t):
                    out.append(
                        MatchReason(Reason.BRAND_FUZZY, t, label, where, detail=f"distance={d}")
                    )
                    matched.append(t)

        if not out:
            return out
        rest_text = flat
        for t in matched:
            rest_text = rest_text.replace(t, "", 1)
        fraud = self._exact_fraud(segs, out, rest_text)
        if fraud:
            out.append(MatchReason(Reason.FRAUD_AFFIX, out[0].token, label, where, detail=fraud))
        if sk != label:
            out.append(MatchReason(Reason.HOMOGLYPH, out[0].token, label, where, detail=sk))
        return out

    def _exact_fraud(
        self, segs: list[str], reasons: list[MatchReason], rest_text: str
    ) -> str | None:
        """诈骗词缀只认连字符整段，或与 BRAND_COMBO.detail 完全相同的剩余段。

        rest_text 已去掉品牌词（含记入 matched 的模糊命中）。词缀只是剩余文本里的子串时不算。
        """
        for affix in self._fraud:
            if affix not in rest_text:
                continue
            if affix in segs or any(
                r.reason == Reason.BRAND_COMBO and r.detail == affix for r in reasons
            ):
                return affix
        return None
