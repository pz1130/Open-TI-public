"""数据主体请求（DSAR，设计文档 2.5）：按邮箱或姓名检索平台中的个人信息，确认后删除或匿名化。

原始数据与泄露账户记录直接删除；发现、文档、告警快照、报告与研判反馈中的文本替换为 [REDACTED]。
证据截图无法自动处理，只列出供人工评估；审计日志不可修改（哈希链），只计数。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import Text, cast, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from opti.core.documents import build_search_text
from opti.db.models import (
    Alert,
    AuditLog,
    Document,
    Evidence,
    ExposedAccount,
    Feedback,
    Finding,
    RawItemRow,
    Report,
)

REDACTED = "[REDACTED]"
MIN_LENGTH = 3
SAMPLE = 20


class DsarError(ValueError):
    pass


@dataclass(frozen=True)
class Subject:
    kind: Literal["email", "name"]
    value: str

    @property
    def digest(self) -> str:
        """写入审计日志的主体标识：规范化后的 SHA-256，不含明文。"""
        return hashlib.sha256(f"{self.kind}:{self.value.casefold()}".encode()).hexdigest()

    @property
    def pattern(self) -> re.Pattern[str]:
        return re.compile(re.escape(self.value), re.IGNORECASE)

    @property
    def like(self) -> str:
        escaped = self.value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"%{escaped}%"


def subject(*, email: str | None = None, name: str | None = None) -> Subject:
    if (email is None) == (name is None):
        raise DsarError("必须且只能指定 --email 或 --name 之一")
    if email is not None:
        value = email.strip()
        if "@" not in value or len(value) < MIN_LENGTH:
            raise DsarError("邮箱格式不对")
        return Subject("email", value)
    value = " ".join((name or "").split())
    if len(value) < MIN_LENGTH:
        raise DsarError(f"姓名至少 {MIN_LENGTH} 个字符")
    return Subject("name", value)


def scrub(value: Any, pattern: re.Pattern[str]) -> Any:
    if isinstance(value, str):
        return pattern.sub(REDACTED, value)
    if isinstance(value, list):
        return [scrub(v, pattern) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v, pattern) for k, v in value.items()}
    return value


@dataclass
class DsarHits:
    exposed_accounts: list[int] = field(default_factory=list)
    raw_items: list[str] = field(default_factory=list)
    findings: list[int] = field(default_factory=list)
    documents: list[int] = field(default_factory=list)
    alerts: list[int] = field(default_factory=list)
    reports: list[int] = field(default_factory=list)
    feedback: list[int] = field(default_factory=list)
    evidence_review: list[int] = field(default_factory=list)  # 截图可能含个人信息：需人工评估
    audit_log: int = 0  # 不可修改，只计数

    def _lists(self) -> dict[str, list[Any]]:
        return {
            "exposed_accounts": self.exposed_accounts, "raw_items": self.raw_items, "findings": self.findings,
            "documents": self.documents, "alerts": self.alerts, "reports": self.reports,
            "feedback": self.feedback, "evidence_review": self.evidence_review,
        }  # fmt: skip

    def counts(self) -> dict[str, int]:
        return {**{k: len(v) for k, v in self._lists().items()}, "audit_log": self.audit_log}

    def samples(self) -> dict[str, list[Any]]:
        return {k: v[:SAMPLE] for k, v in self._lists().items() if v}


async def search(session: AsyncSession, subj: Subject) -> DsarHits:
    def hit(column: Any) -> ColumnElement[bool]:
        return column.ilike(subj.like, escape="\\")  # type: ignore[no-any-return]

    async def ids(stmt: Any) -> list[Any]:
        return sorted(set((await session.scalars(stmt)).all()))

    hits = DsarHits()
    if subj.kind == "email":
        hits.exposed_accounts = await ids(
            select(ExposedAccount.id).where(
                func.lower(ExposedAccount.email) == subj.value.casefold()
            )
        )
    hits.raw_items = await ids(
        select(RawItemRow.item_id).where(hit(cast(RawItemRow.payload, Text)))
    )
    hits.findings = await ids(select(Finding.id).where(hit(cast(Finding.match, Text))))
    hits.documents = await ids(
        select(Document.id).where(
            or_(hit(Document.title), hit(Document.snippet), hit(cast(Document.contexts, Text)))
        )
    )
    hits.alerts = await ids(select(Alert.id).where(hit(cast(Alert.routing, Text))))
    hits.reports = await ids(select(Report.id).where(hit(cast(Report.content, Text))))
    hits.feedback = await ids(select(Feedback.id).where(hit(Feedback.reason)))
    if hits.findings:
        hits.evidence_review = await ids(
            select(Evidence.id).where(Evidence.finding_id.in_(hits.findings))
        )
    hits.audit_log = int(
        await session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(or_(hit(cast(AuditLog.detail, Text)), hit(AuditLog.actor)))
        )
        or 0
    )
    return hits


async def erase(session: AsyncSession, subj: Subject) -> dict[str, int]:
    """删除原始数据与泄露账户记录，其余位置的文本匿名化。返回处理前的命中数量。"""
    hits = await search(session, subj)
    pattern = subj.pattern
    if hits.exposed_accounts:
        await session.execute(
            delete(ExposedAccount).where(ExposedAccount.id.in_(hits.exposed_accounts))
        )
    if hits.raw_items:
        await session.execute(delete(RawItemRow).where(RawItemRow.item_id.in_(hits.raw_items)))
    for f in await session.scalars(select(Finding).where(Finding.id.in_(hits.findings))):
        f.match = scrub(f.match, pattern)
    for d in await session.scalars(select(Document).where(Document.id.in_(hits.documents))):
        d.title, d.snippet = scrub(d.title, pattern), scrub(d.snippet, pattern)
        d.contexts = scrub(list(d.contexts), pattern)
        d.search_text = build_search_text(d.title, d.snippet, d.contexts)
    for a in await session.scalars(select(Alert).where(Alert.id.in_(hits.alerts))):
        a.routing = scrub(a.routing, pattern)
    for r in await session.scalars(select(Report).where(Report.id.in_(hits.reports))):
        r.content = scrub(r.content, pattern)
    for fb in await session.scalars(select(Feedback).where(Feedback.id.in_(hits.feedback))):
        fb.reason = scrub(fb.reason, pattern)
    await session.flush()
    return hits.counts()
