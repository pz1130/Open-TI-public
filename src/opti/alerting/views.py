"""告警视图：推送消息需要的最小信息集合，不含个人信息（设计文档 13）。"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.db.models import Alert, AlertFinding, Finding

SEVERITY_LABEL = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息"}
CATEGORY_LABEL = {
    "vulnerability": "已被利用漏洞",
    "threat_intel": "威胁情报",
    "credential_exposure": "凭据暴露",
    "ransomware_mention": "勒索泄露站提及",
    "secret_leak": "密钥泄露",
    "data_leak": "代码中的内部信息",
    "brand_mention": "一般提及",
    "negative_press": "负面舆情",
    "fraud_scam": "冒名诈骗",
    "phishing_site": "钓鱼网站",
    "typosquat_domain": "仿冒域名",
    "unapproved_certificate": "未经批准的证书",
    "certificate_expiry": "证书即将到期或已过期",
    "impersonation_account": "冒充社交账号",
}


def defang(domain: str) -> str:
    """去链接化，避免在聊天工具/邮件中生成可点击的恶意链接。"""
    return domain.replace(".", "[.]")


@dataclass(frozen=True)
class AlertView:
    alert_id: int
    project_id: str
    severity: str
    category: str
    domain: str
    score: int
    reasons: tuple[str, ...]
    first_seen: datetime
    created_at: datetime
    link: str


def _snapshot(alert: Alert) -> tuple[str, str, int, tuple[str, ...]]:
    """开告警时写入 routing 的评分、类别、域名和原因。不读后来被覆盖的 finding。"""
    snap = alert.routing if isinstance(alert.routing, dict) else {}
    raw_reasons = snap.get("reasons")
    reasons = tuple(str(item) for item in raw_reasons) if isinstance(raw_reasons, list) else ()
    raw_score = snap.get("score")
    score = raw_score if isinstance(raw_score, int) else 0
    raw_category = snap.get("category")
    category = raw_category if isinstance(raw_category, str) else ""
    raw_domain = snap.get("domain")
    domain = raw_domain if isinstance(raw_domain, str) else ""
    return category, domain, score, reasons


async def load_views(
    session: AsyncSession, alert_ids: Sequence[int], base_url: str
) -> list[AlertView]:
    if not alert_ids:
        return []
    rows = await session.execute(
        select(Alert, Finding)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .join(Finding, Finding.id == AlertFinding.finding_id)
        .where(Alert.id.in_(list(alert_ids)))
        .order_by(Alert.id)
    )
    views: list[AlertView] = []
    for alert, finding in rows:
        category, domain, score, reasons = _snapshot(alert)
        views.append(
            AlertView(
                alert_id=alert.id,
                project_id=alert.project_id,
                severity=alert.severity,
                category=category,
                domain=domain,
                score=score,
                reasons=reasons,
                first_seen=finding.first_seen,
                created_at=alert.created_at,
                link=f"{base_url.rstrip('/')}/alerts/{alert.id}",
            )
        )
    return views


@dataclass(frozen=True)
class Notice:
    """运营提醒（下架 SLA 超时等）：与告警走同一组渠道，同样不含个人信息，只给链接回平台。"""

    title: str
    facts: tuple[tuple[str, str], ...]
    link: str
