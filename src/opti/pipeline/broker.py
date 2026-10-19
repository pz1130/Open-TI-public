"""任务队列：生产用 Valkey（RedisStreamBroker，带确认，至少一次投递）；未配置时用进程内 broker。"""

from __future__ import annotations

import os

from taskiq import AsyncBroker, InMemoryBroker, SimpleRetryMiddleware
from taskiq_redis import RedisStreamBroker

# 任务抛异常时消息照样确认；只有带 retry_on_error 标签的幂等任务（ingest）自动重试，否则这条数据就丢了。
INGEST_RETRIES = 3


def make_broker(url: str | None) -> AsyncBroker:
    broker: AsyncBroker = (
        InMemoryBroker(await_inplace=True) if not url else RedisStreamBroker(url, queue_name="opti")
    )
    return broker.with_middlewares(SimpleRetryMiddleware(default_retry_count=INGEST_RETRIES))


broker = make_broker(os.environ.get("OPTI_BROKER_URL"))
