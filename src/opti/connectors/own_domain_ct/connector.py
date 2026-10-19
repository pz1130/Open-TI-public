"""使用机构 自有域名证书监控：CT 中出现官方域名的新证书时，检查签发 CA 是否经过批准。"""

from __future__ import annotations

from typing import Any, ClassVar

from opti.connectors.certstream.connector import CertstreamConnector, unique_domains
from opti.connectors.certstream.parser import CertEvent
from opti.core.domain_match import DomainMatch


class OwnDomainCtConnector(CertstreamConnector):
    id: ClassVar[str] = "own_domain_ct"

    def select(self, event: CertEvent) -> list[DomainMatch]:
        out: list[DomainMatch] = []
        for d in event.all_domains:
            m = self._matcher.match(d) if self._matcher.could_match(d) else None
            if m is not None and m.status == "official":
                out.append(m)
        return unique_domains(out)

    def extra_payload(self, event: CertEvent) -> dict[str, Any]:
        approved = {str(a).casefold() for a in self.config.get("approved_issuers", [])}
        issuer = (event.issuer_o or "").casefold()
        return {"issuer_approved": (issuer in approved) if approved else None}
