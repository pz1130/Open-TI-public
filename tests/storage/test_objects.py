import hashlib
from collections.abc import Iterator

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from opti.sdk.context import EnvSecretProvider
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore, S3ObjectStore, object_store_from_settings


async def test_memory_store_round_trip() -> None:
    store = MemoryObjectStore()
    obj = await store.put("evidence/aa/x.png", b"png", "image/png")
    assert obj.sha256 == hashlib.sha256(b"png").hexdigest() and obj.size == 3
    assert await store.get("evidence/aa/x.png") == b"png"
    again = await store.put("evidence/aa/x.png", b"png2", "image/png")
    assert again.version_id != obj.version_id


@pytest.fixture
def s3_store() -> Iterator[S3ObjectStore]:
    with mock_aws():
        yield S3ObjectStore(boto3.client("s3", region_name="us-east-1"), "opti-evidence")


async def test_s3_store_creates_versioned_bucket_and_round_trips(s3_store: S3ObjectStore) -> None:
    await s3_store.ensure_bucket()
    await s3_store.ensure_bucket()  # 幂等
    obj = await s3_store.put("evidence/ab/abc.html", b"<html></html>", "text/html")
    assert obj.version_id  # 已启用版本控制
    assert obj.sha256 == hashlib.sha256(b"<html></html>").hexdigest()
    assert await s3_store.get("evidence/ab/abc.html") == b"<html></html>"


def test_store_from_settings_requires_endpoint() -> None:
    assert object_store_from_settings(Settings(), EnvSecretProvider({})) is None
    store = object_store_from_settings(
        Settings(s3_endpoint="http://seaweedfs:8333"),
        EnvSecretProvider(
            {"OPTI_SECRET_OBJSTORE_ACCESS_KEY": "a", "OPTI_SECRET_OBJSTORE_SECRET_KEY": "b"}
        ),
    )
    assert isinstance(store, S3ObjectStore)


async def test_delete(s3_store: S3ObjectStore) -> None:
    await s3_store.ensure_bucket()
    obj = await s3_store.put("evidence/cd/x.png", b"png", "image/png")
    await s3_store.delete(obj.key, obj.version_id)
    with pytest.raises(ClientError):
        await s3_store.get(obj.key)
    memory = MemoryObjectStore()
    await memory.put("k", b"x", "text/plain")
    await memory.delete("k")
    await memory.delete("missing")  # 不存在时不报错
    assert memory.objects == {}
