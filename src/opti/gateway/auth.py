"""采集节点认证与下发规则（设计文档 2.5、3.4）。"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import Any

from opti.core.config import ProjectRules
from opti.sdk.context import SecretProvider

MIN_TOKEN_LEN = 32


class NodeAuth:
    """mTLS 之外的第二道认证：每个节点一个令牌，并据此识别节点 ID。"""

    def __init__(self, tokens: Mapping[str, str]) -> None:
        self._tokens = {node: token.encode() for node, token in tokens.items()}

    @classmethod
    def from_secrets(cls, nodes: Sequence[str], secrets: SecretProvider) -> NodeAuth:
        if not nodes:
            raise ValueError("需要设置 OPTI_GATEWAY_NODES（逗号分隔的采集节点 ID）")
        tokens: dict[str, str] = {}
        for node in nodes:
            token = secrets.get("gateway", f"node_{node}")
            if not token or len(token) < MIN_TOKEN_LEN:
                raise ValueError(
                    f"采集节点 {node} 的令牌未设置或少于 {MIN_TOKEN_LEN} 个字符"
                    f"（OPTI_SECRET_GATEWAY_NODE_{node.upper()}）"
                )
            tokens[node] = token
        return cls(tokens)

    def identify(self, authorization: str | None) -> str | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        presented = authorization.removeprefix("Bearer ").encode()
        found: str | None = None
        for node, token in self._tokens.items():  # 逐个比较，不提前返回
            if hmac.compare_digest(presented, token):
                found = node
        return found


def overseas_rules(rules: ProjectRules) -> dict[str, Any]:
    """下发到境外节点的规则：去掉人员类关键词集合（设计文档 2.5）。"""
    data = rules.model_dump(mode="json")
    data["sets"] = {name: s for name, s in data["sets"].items() if s.get("type") != "executive"}
    return data


def rules_digest(data: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
