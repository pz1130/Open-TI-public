"""域名命中与离线评分解释（命令行 match-domain 与研判界面的测试沙盒共用）。纯逻辑，不联网。"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from opti.core.domain_match import DomainMatcher
from opti.core.scoring import DomainSignals, Score, score_domain


def score_dict(s: Score) -> dict[str, Any]:
    return {
        "value": s.value,
        "severity": s.severity.value,
        "category": s.category.value,
        "breakdown": s.breakdown,
    }


def domain_report(matcher: DomainMatcher, raw: str) -> dict[str, Any]:
    m = matcher.match(raw)
    if m is None:
        return {"input": raw, "status": "no_match"}
    out: dict[str, Any] = {
        "input": raw,
        "domain": m.domain,
        "registered": m.registered,
        "status": m.status,
        "reasons": [asdict(r) for r in m.reasons],
    }
    if m.status == "match":
        # 沙盒不富化：注册时间、页面特征等因子按"未观测"处理，分数是下限
        out["score"] = score_dict(score_domain(DomainSignals(match=m)))
    return out
