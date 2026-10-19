"""S3 兼容对象存储（设计文档 11）：证据截图、HTML 快照。优先复用使用机构现有存储，开发环境用 SeaweedFS。"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from opti.sdk.context import SecretProvider
from opti.settings import Settings

log = logging.getLogger("opti.storage")


@dataclass(frozen=True)
class StoredObject:
    key: str
    sha256: str
    size: int
    version_id: str | None


class ObjectStore(Protocol):
    async def put(self, key: str, data: bytes, content_type: str) -> StoredObject: ...

    async def get(self, key: str) -> bytes: ...

    async def delete(self, key: str, version_id: str | None = None) -> None: ...


class MemoryObjectStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self._versions = 0

    async def put(self, key: str, data: bytes, content_type: str) -> StoredObject:
        self._versions += 1
        self.objects[key] = data
        return StoredObject(key, hashlib.sha256(data).hexdigest(), len(data), str(self._versions))

    async def get(self, key: str) -> bytes:
        return self.objects[key]

    async def delete(self, key: str, version_id: str | None = None) -> None:
        self.objects.pop(key, None)


class S3ObjectStore:
    """boto3 是同步库，放到线程中执行。"""

    def __init__(self, client: Any, bucket: str) -> None:
        self._c = client
        self._bucket = bucket

    async def ensure_bucket(self) -> None:
        def run() -> None:
            try:
                self._c.head_bucket(Bucket=self._bucket)
            except ClientError:
                self._c.create_bucket(Bucket=self._bucket)
            try:
                self._c.put_bucket_versioning(
                    Bucket=self._bucket, VersioningConfiguration={"Status": "Enabled"}
                )
            except (
                ClientError
            ) as e:  # 部分 S3 兼容实现不支持；证据仍按内容寻址，不会被覆盖成别的内容
                log.warning("对象存储未能启用版本控制：%s", e.response.get("Error", {}).get("Code"))

        await asyncio.to_thread(run)

    async def put(self, key: str, data: bytes, content_type: str) -> StoredObject:
        sha = hashlib.sha256(data).hexdigest()
        resp = await asyncio.to_thread(
            self._c.put_object,
            Bucket=self._bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            Metadata={"sha256": sha},
        )
        return StoredObject(key, sha, len(data), resp.get("VersionId"))

    async def get(self, key: str) -> bytes:
        def run() -> bytes:
            body = self._c.get_object(Bucket=self._bucket, Key=key)["Body"]
            return bytes(body.read())

        return await asyncio.to_thread(run)

    async def delete(self, key: str, version_id: str | None = None) -> None:
        """Delete the stored version, rather than leaving a versioned delete marker."""
        extra = {"VersionId": version_id} if version_id else {}
        await asyncio.to_thread(self._c.delete_object, Bucket=self._bucket, Key=key, **extra)


def object_store_from_settings(settings: Settings, secrets: SecretProvider) -> S3ObjectStore | None:
    if not settings.s3_endpoint:
        return None
    client = boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        region_name=settings.s3_region,
        aws_access_key_id=secrets.get("objstore", "access_key"),
        aws_secret_access_key=secrets.get("objstore", "secret_key"),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )
    return S3ObjectStore(client, settings.s3_bucket)
