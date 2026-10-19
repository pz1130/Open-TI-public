"""在采集节点上执行网关下发的任务（设计文档 3.4）。"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from opti.collector.uploader import ItemUploader
from opti.core.config import ProjectRules
from opti.gateway.jobs import Job
from opti.sdk.base import BaseConnector, Enricher
from opti.sdk.context import MemoryCursorStore
from opti.sdk.manifest import ManifestError
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry
from opti.sdk.runtime import ConnectorBlocked, RuntimePaths, collect, create
from opti.sdk.scan import KeywordScan, scan_plan
from opti.storage.artifacts import ArtifactError, ArtifactSaver, offload_artifacts

log = logging.getLogger("opti.collector.runner")


class JobRunner:
    def __init__(
        self,
        *,
        registry: Registry,
        rules: ProjectRules,
        paths: RuntimePaths,
        uploader: ItemUploader,
        saver: ArtifactSaver,
        enrich_timeout: float = 80.0,
    ) -> None:
        self._registry = registry
        self._rules = rules
        self._paths = paths
        self._uploader = uploader
        self._saver = saver
        self._enrich_timeout = enrich_timeout
        self._enrichers: dict[str, Enricher] = {}

    async def run(self, job: Job) -> dict[str, Any]:
        if job.kind == "enrich":
            return await self._enrich(job.payload)
        return await self._run_connector(job.payload)

    def _enricher(self, eid: str) -> Enricher:
        if eid not in self._enrichers:
            if self._registry.manifest(eid).egress == "domestic":
                raise ConnectorBlocked(f"{eid} 只能在境内运行")
            e = create(self._registry, eid, self._rules, paths=self._paths)
            if not isinstance(e, Enricher):
                raise ConnectorBlocked(f"{eid} 不是富化器")
            self._enrichers[eid] = e
        return self._enrichers[eid]

    async def _enrich(self, p: dict[str, Any]) -> dict[str, Any]:
        eid = str(p.get("enricher"))
        try:
            enricher = self._enricher(eid)
            data = await asyncio.wait_for(
                enricher.enrich(str(p.get("type")), str(p.get("value"))), self._enrich_timeout
            )
            return await offload_artifacts(data, self._saver)
        except (ConnectorBlocked, ManifestError) as e:
            return {"error": f"blocked: {e}"}
        except ArtifactError as e:
            return {"error": f"artifact: {e}"}
        except Exception as e:  # 富化器缺陷或超时不能让节点退出
            log.warning("富化任务 %s 失败：%s", eid, type(e).__name__)
            return {"error": type(e).__name__}

    async def _run_connector(self, p: dict[str, Any]) -> dict[str, Any]:
        cid = str(p.get("connector_id"))
        cursors = MemoryCursorStore()
        for key, value in dict(p.get("cursors") or {}).items():
            cursors.set(cid, str(key), str(value))
        items, status, message = 0, "ok", ""
        conn: BaseConnector | Enricher | None = None
        try:
            if self._registry.manifest(cid).egress == "domestic":
                raise ConnectorBlocked(f"{cid} 只能在境内运行")
            rules = self._rules
            selection = p.get("keyword_scan")
            scan = None
            if selection is not None:
                rules = ProjectRules.model_validate(selection["rules"])
                scan = KeywordScan.model_validate(selection["scan"])
            plan = scan_plan(rules, scan) if scan is not None else build_query_plan(rules)
            conn = create(self._registry, cid, rules, paths=self._paths, cursors=cursors)
            if not isinstance(conn, BaseConnector):
                raise ConnectorBlocked(f"{cid} 是富化器，不能作为采集任务运行")
            max_items = p.get("max_items")
            seconds = p.get("seconds")
            async for item in collect(
                conn,
                plan,
                max_items=int(max_items) if max_items is not None else None,
                seconds=float(seconds) if seconds is not None else None,
            ):
                await self._uploader.put(item)
                items += 1
        except Exception as e:  # 记录到运行结果，由境内写入 connector_run
            status, message = "error", f"{type(e).__name__}: {e}"
        finally:
            if conn is not None:
                await conn.ctx.http().aclose()
        # 先把本次运行的数据全部回传，再报告游标：游标不能跑到未入库的数据前面
        await self._uploader.flush()
        return {
            "status": status,
            "items": items,
            "message": message[:2000],
            "cursors": cursors.dump(cid),
        }

    async def aclose(self) -> None:
        for e in self._enrichers.values():
            await e.ctx.http().aclose()
        self._enrichers.clear()
