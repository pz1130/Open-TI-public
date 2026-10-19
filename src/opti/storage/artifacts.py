"""富化结果中的证据产物（截图、HTML 快照）：写入对象存储后只保留引用。

富化结果会缓存进 entity.enrichment（JSONB），也会经 Valkey 传输，绝不能带着 base64 数据。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any

from opti.storage.objects import ObjectStore

EVIDENCE_TYPES = {"image/png": "png", "text/html": "html", "application/json": "json"}
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
ArtifactSaver = Callable[[bytes, str], Awaitable[dict[str, Any]]]


class ArtifactError(Exception):
    pass


def _media_type(content_type: str) -> str:
    return content_type.split(";")[0].strip().lower()


def evidence_key(sha256: str, content_type: str) -> str:
    ext = EVIDENCE_TYPES.get(_media_type(content_type))
    if ext is None:
        raise ArtifactError(f"不接受的证据类型：{content_type}")
    return f"evidence/{sha256[:2]}/{sha256}.{ext}"


def store_saver(store: ObjectStore, *, node_id: str = "local") -> ArtifactSaver:
    async def save(data: bytes, content_type: str) -> dict[str, Any]:
        sha = hashlib.sha256(data).hexdigest()
        obj = await store.put(evidence_key(sha, content_type), data, _media_type(content_type))
        return {
            "key": obj.key,
            "sha256": obj.sha256,
            "size": obj.size,
            "version_id": obj.version_id,
            "node_id": node_id,
        }

    return save


async def offload_artifacts(result: dict[str, Any], save: ArtifactSaver | None) -> dict[str, Any]:
    """把 data_b64 产物交给 save 存储并替换为引用；save 为 None 时直接丢弃数据。"""
    arts = result.get("artifacts")
    if not isinstance(arts, list):
        return result
    out: list[dict[str, Any]] = []
    for a in arts:
        if not isinstance(a, dict):
            continue
        if "data_b64" not in a:
            out.append(a)
            continue
        if save is None:
            continue
        try:
            data = base64.b64decode(str(a["data_b64"]), validate=True)
        except (binascii.Error, ValueError) as e:
            raise ArtifactError("产物不是合法的 base64") from e
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ArtifactError(f"产物超过 {MAX_ARTIFACT_BYTES} 字节")
        content_type = str(a.get("content_type") or "")
        ref = await save(data, content_type)
        out.append(
            {"name": str(a.get("name") or ""), "content_type": _media_type(content_type), **ref}
        )
    return {**result, "artifacts": out}
