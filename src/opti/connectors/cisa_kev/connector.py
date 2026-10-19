"""CISA 已被利用漏洞目录（设计文档 4.8）：公开 JSON，无需密钥。

只回传新增或内容有变化的条目；与本机构软件清单的比对在平台处理器中进行（清单不下发到采集节点）。
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from opti.core.kev import digest, kev_payload
from opti.sdk.base import BaseConnector
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
MAX_CATALOG_BYTES = 20 * 1024 * 1024


class CisaKevConnector(BaseConnector):
    id: ClassVar[str] = "cisa_kev"
    tier: ClassVar[Tier] = Tier.FREE

    def _seen(self) -> dict[str, str]:
        try:
            seen: Any = json.loads(self.ctx.get_cursor("digests") or "{}")
        except ValueError:
            return {}
        return {str(k): str(v) for k, v in seen.items()} if isinstance(seen, dict) else {}

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        log = self.ctx.logger()
        endpoint = str(self.config.get("api_base", API))
        try:
            resp = await self.ctx.http().get(endpoint, max_body_bytes=MAX_CATALOG_BYTES)
            doc = resp.json()
        except HttpError as e:
            if e.status != 403 or endpoint != API:
                log.warning("下载 KEV 目录失败：%s", e)
                return
            # CISA 的站点有时按网络出口拒绝 JSON 下载；使用 CISA 维护的公开镜像。
            try:
                resp = await self.ctx.http().get(MIRROR, max_body_bytes=MAX_CATALOG_BYTES)
                doc = resp.json()
            except (HttpError, ValueError) as mirror_error:
                log.warning("下载 KEV 目录及 CISA 镜像失败：%s", mirror_error)
                return
        except ValueError as e:
            log.warning("下载 KEV 目录失败：%s", e)
            return
        vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
        if not isinstance(vulns, list):
            log.warning("KEV 目录格式不对（缺少 vulnerabilities）")
            return
        count = doc.get("count")
        if isinstance(count, int) and count != len(vulns):
            log.warning("KEV 目录 count 与 vulnerabilities 长度不符")
            return
        version = str(doc.get("catalogVersion") or "")
        seen = self._seen()
        current: dict[str, str] = {}
        for raw in vulns:
            payload = kev_payload(raw) if isinstance(raw, dict) else None
            if payload is None:
                continue
            cve = payload["kev"]["cve"]
            current[cve] = d = digest(payload)
            if seen.get(cve) != d:
                yield RawItem(
                    connector_id=self.id, source_item_id=f"{cve}#{d}", fetched_at=utcnow(), url=None,
                    payload=payload, project_ids=plan.project_ids,
                )  # fmt: skip
        # 全部产出后才推进游标：中途停止（如 --max-items）时下次重新回传，处理器幂等
        self.ctx.set_cursor("digests", json.dumps(current, sort_keys=True, separators=(",", ":")))
        if version:
            self.ctx.set_cursor("version", version)
