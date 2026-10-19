"""ATT&CK STIX 2.1 目录与保守的告警候选技术映射。"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import TypedDict, cast


class AttackTag(TypedDict):
    id: str
    name: str
    tactics: list[str]
    url: str


class AttackEntry(AttackTag):
    stix_id: str
    modified: str


# 类别只表示与技术相关，不能证明技术已由对手实际执行。
_CANDIDATES = {
    "phishing_site": "T1566",
    "reported_phishing": "T1566",
    "clone_site": "T1566",
    "typosquat_domain": "T1583.001",
    "impersonation_account": "T1585.001",
}


@lru_cache(maxsize=1)
def catalog() -> dict[str, AttackEntry]:
    data = json.loads(Path(__file__).with_name("attack_catalog.json").read_text(encoding="utf-8"))
    return {item["id"]: item for item in cast(list[AttackEntry], data["techniques"])}


def candidate_tags(category: str) -> list[AttackTag]:
    """仅返回可供分析员参考的候选标签；未覆盖类别不猜测。"""
    tid = _CANDIDATES.get(category)
    if tid is None:
        return []
    entry = catalog()[tid]
    return [
        {
            "id": tid,
            "name": entry["name"],
            "tactics": list(entry["tactics"]),
            "url": entry["url"],
        }
    ]
