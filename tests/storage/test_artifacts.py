import base64
import hashlib

import pytest

from opti.storage.artifacts import (
    MAX_ARTIFACT_BYTES,
    ArtifactError,
    evidence_key,
    offload_artifacts,
    store_saver,
)
from opti.storage.objects import MemoryObjectStore

PNG = b"\x89PNG fake"
SHA = hashlib.sha256(PNG).hexdigest()


def _result(data: bytes = PNG) -> dict[str, object]:
    return {
        "final_url": "https://sbr-loans.com/",
        "artifacts": [
            {"name": "screenshot", "content_type": "image/png",
             "data_b64": base64.b64encode(data).decode()},
        ],
    }  # fmt: skip


def test_evidence_key_is_content_addressed() -> None:
    assert evidence_key(SHA, "image/png") == f"evidence/{SHA[:2]}/{SHA}.png"
    assert evidence_key(SHA, "text/html; charset=utf-8").endswith(".html")
    with pytest.raises(ArtifactError):
        evidence_key(SHA, "application/x-msdownload")


async def test_offload_replaces_data_with_reference() -> None:
    store = MemoryObjectStore()
    out = await offload_artifacts(_result(), store_saver(store, node_id="hk1"))
    [ref] = out["artifacts"]
    assert "data_b64" not in ref
    assert ref["sha256"] == SHA and ref["size"] == len(PNG) and ref["node_id"] == "hk1"
    assert ref["name"] == "screenshot" and ref["content_type"] == "image/png"
    assert store.objects[ref["key"]] == PNG
    assert out["final_url"] == "https://sbr-loans.com/"


async def test_offload_without_saver_drops_data() -> None:
    """没有对象存储时也不能把 base64 留在结果里（结果会写进 entity.enrichment）。"""
    out = await offload_artifacts(_result(), None)
    assert out["artifacts"] == []


async def test_result_without_artifacts_is_unchanged() -> None:
    assert await offload_artifacts({"title": "x"}, None) == {"title": "x"}


async def test_oversized_artifact_is_rejected() -> None:
    with pytest.raises(ArtifactError):
        await offload_artifacts(
            _result(b"x" * (MAX_ARTIFACT_BYTES + 1)), store_saver(MemoryObjectStore())
        )
