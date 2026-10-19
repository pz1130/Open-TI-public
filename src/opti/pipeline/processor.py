"""处理器（设计文档 3.2）：原始数据 → 实体 → 富化 → 评分 → Finding → 告警 → 监视列表。幂等。"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core import policy
from opti.core.adjudication import LlmSource, eligible
from opti.core.code_adjudication import eligible_code, select_secrets, summarize_secrets
from opti.core.codehits import (
    code_facts,
    disclosure_links,
    merge_hits,
    parse_code_hit,
    repo_value,
    safe_scan,
)
from opti.core.config import ProjectRules
from opti.core.documents import DocumentError, parse_document, select_contexts
from opti.core.domain_match import DomainMatch, DomainMatcher
from opti.core.domains import parse_domain
from opti.core.exposure import ExposureError, parse_exposure
from opti.core.kev import KevError, SoftwareMatcher, parse_kev
from opti.core.languages import detect_language
from opti.core.leakposts import LeakPostError, parse_post
from opti.core.scoring import (
    LLM_POINTS,
    SIGNAL_POINTS,
    SIGNALS,
    Category,
    RansomFacts,
    Score,
    SignalFacts,
    TextFacts,
    VulnFacts,
    code_reasons,
    exposure_reasons,
    score_code,
    score_domain,
    score_exposure,
    score_own_domain_cert,
    score_ransomware,
    score_signal,
    score_text,
    score_url,
    score_vulnerability,
    severity_for,
    severity_rank,
    text_reasons,
    vuln_reasons,
    with_code_llm,
    with_llm,
    with_signal,
)
from opti.core.secret_guard import mask_item
from opti.core.text_match import TextMatcher
from opti.core.urls import UrlMatch, UrlMatcher, normalize_url
from opti.core.vendors import PartyMatcher, ransomware_reasons
from opti.db import repo
from opti.db.models import Entity, ExposedAccount, Finding, KevEntry, LeakPost, WatchedDomain
from opti.enrichers.signals import build_domain_signals, build_url_signals
from opti.pipeline import adjudication, coderepos, documents, kev, leakposts, suppression, watchlist
from opti.pipeline.enrichment import Clock, EnrichmentService, utcnow
from opti.sdk.models import RawItem

MAX_INDICATORS = 50
MAX_CONTEXT_BYTES = 16 * 1024
WATCH_SIGNALS = frozenset({"canary", "hotlink"})
log = logging.getLogger("opti.processor")

DEFAULT_ENRICHERS = (
    "dns",
    "rdap",
    "tranco",
    "http_probe",
    "botnet_feed",
    "greynoise",
    "abuseipdb",
    "pulsedive",
)


@dataclass
class ProcessResult:
    stored: bool = False
    findings: list[int] = field(default_factory=list)
    alerts: list[int] = field(default_factory=list)
    watched: list[str] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)


class Processor:
    def __init__(
        self,
        rules: ProjectRules,
        enrichment: EnrichmentService,
        *,
        enrich_ids: Sequence[str] = DEFAULT_ENRICHERS,
        clock: Clock = utcnow,
        parties: PartyMatcher | None = None,
        software: SoftwareMatcher | None = None,
        llm: LlmSource | None = None,
        leak_link_hosts: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self.rules = rules
        self.enrichment = enrichment
        self._enrich_ids = tuple(enrich_ids)
        self._clock = clock
        self._matcher = DomainMatcher(rules.domains)
        self._url_matcher = UrlMatcher(rules)
        self._text_matcher = TextMatcher(rules)
        self._parties = parties
        self.software = software
        self.llm = llm
        self._leak_link_hosts = leak_link_hosts or {}

    async def process(
        self, session: AsyncSession, item: RawItem, *, sync_project: bool = True
    ) -> ProcessResult:
        # 设计文档 2.3 / RED Team 4：入库前统一遮蔽凭据（不依赖采集节点是否已遮蔽）
        item = mask_item(item)
        if isinstance(item.payload.get("indicators"), list):
            context = item.payload.get("context") or {}
            if (
                not isinstance(context, dict)
                or len(json.dumps(context, ensure_ascii=False).encode()) > MAX_CONTEXT_BYTES
            ):
                raise ValueError("指标上下文超过 16 KB 或格式不合法")
            item = replace(
                item,
                payload={**item.payload, "indicators": item.payload["indicators"][:MAX_INDICATORS]},
            )
        stored_item = item
        document = item.payload.get("document")
        if isinstance(document, dict) and document.get("text"):
            body = str(document["text"])
            stored_document = {
                **document,
                "text": "",
                "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "text_length": len(body),
            }
            stored_item = replace(
                stored_item,
                payload={**stored_item.payload, "document": stored_document},
            )
        safe: dict[str, Any]
        if "leak_post" in item.payload:
            try:
                post = parse_post(
                    item.payload, allow_hosts=self._leak_link_hosts.get(item.connector_id)
                )
                if post.source != item.connector_id:
                    raise LeakPostError("来源不一致")
                safe = {
                    "key": post.key,
                    "source": post.source,
                    "group": post.group,
                    "victim": post.victim,
                    "domain": post.domain,
                    "country": post.country,
                    "activity": post.activity,
                    "discovered": post.discovered.isoformat(),
                    "published": post.published.isoformat() if post.published else None,
                    "description": post.description,
                    "links": list(post.links),
                    "other_links": list(post.other_links),
                }
            except LeakPostError:
                safe = {"invalid": True}
            stored_item = replace(item, url=None, payload={"leak_post": safe})
        if "code_hit" in item.payload:
            try:
                hit = parse_code_hit(item.payload["code_hit"])
                stored_item = replace(item, url=hit["html_url"], payload={"code_hit": hit})
            except ValueError:
                stored_item = replace(item, url=None, payload={"code_hit": {"invalid": True}})
        if "exposure" in item.payload:
            # 只保留经过白名单整理的公开字段；原始邮件地址仅写入 exposed_account。
            try:
                ex = parse_exposure(item.payload["exposure"], self.rules.domains.official)
                safe = {
                    **ex.public(),
                    "key": ex.key,
                    "accounts": [],
                    "accounts_count": len(ex.accounts),
                }
            except ExposureError:
                safe = {"invalid": True, "accounts": []}
            stored_item = replace(item, url=None, payload={"exposure": safe})
        if item.connector_id == "public_report":
            context = {**item.payload.get("context", {}), "contact": None}
            stored_item = replace(item, payload={**item.payload, "context": context})
        if sync_project:
            await repo.upsert_project(session, self.rules)
        result = ProcessResult(stored=await repo.insert_raw_item(session, stored_item))
        if self.rules.project not in item.project_ids:
            return result
        # 已有观测就返回，避免 TTL 过后重放重新评分并再开告警。其他项目仍可处理同一 item_id。
        if await repo.has_project_observation(session, self.rules.project, item.item_id):
            return ProcessResult(stored=False)
        if isinstance(item.payload.get("feed_url"), str):
            await self._feed_url(session, item, result)
            return result
        if "kev" in item.payload:
            await self._kev(session, item, result)
            return result
        if "exposure" in item.payload:
            await self._exposure(session, item, result)
            return result
        if "leak_post" in item.payload:
            await self._leak_post(session, item, result)
            return result
        if "code_hit" in item.payload:
            await self._code_hit(session, item, result)
            return result
        if isinstance(item.payload.get("document"), dict):
            await self._document(session, item, result)
            return result
        if isinstance(item.payload.get("indicators"), list):
            await self._indicators(session, item, result)
            return result
        seen: set[str] = set()
        for md in item.payload.get("matches", []):
            m = self._matcher.match(str(md.get("domain", "")))
            if m is None or m.domain in seen:
                continue
            seen.add(m.domain)
            if m.status in ("match", "official") and await self._suppressed(
                session, m.domain, m.registered
            ):
                # 分析员已确认的误报或合法第三方：不富化（不访问对方站点）、不更新 Finding、不开告警
                result.suppressed.append(m.domain)
                continue
            if m.status == "match":
                await self._brand_domain(session, item, m, result)
            elif m.status == "official" and "issuer_approved" in item.payload:
                await self._own_certificate(session, item, m, result)
        return result

    async def _document(self, session: AsyncSession, item: RawItem, result: ProcessResult) -> None:
        try:
            doc = parse_document(item.payload)
        except DocumentError as exc:
            log.warning("丢弃不合法的文档（%s）：%s", item.connector_id, exc)
            return
        hits = self._text_matcher.match(
            "\n".join(part for part in (doc.title, doc.summary, doc.text) if part)
        )
        matches = [hit for hit in hits if hit.role == "match"]
        if not matches:
            return
        if doc.language is None:
            try:
                detected = await asyncio.to_thread(
                    detect_language, doc.text or f"{doc.title}\n{doc.summary}"
                )
            except Exception as exc:
                log.warning("本地语言识别失败（%s）：%s", item.connector_id, type(exc).__name__)
                detected = None
            doc = replace(doc, language=detected)
        boosters = [hit for hit in hits if hit.role == "booster"]
        now = self._clock()
        contexts = select_contexts([*matches, *boosters])
        row = await documents.upsert(
            session, doc, contexts=contexts, connector=item.connector_id, now=now
        )
        assert row.cluster_id is not None
        entity = await repo.upsert_entity(session, "document", f"cluster:{row.cluster_id}", now)
        previous = await session.scalar(
            select(Finding).where(
                Finding.project_id == self.rules.project,
                Finding.entity_id == entity.id,
            )
        )
        prior = previous.match if previous is not None else {}
        categories = {self.rules.booster_category(hit.set_name) for hit in boosters}
        kind = (
            "intel" if doc.kind == "intel"
            else "fraud" if "fraud_scam" in categories else "press" if "negative_press" in categories else "mention"
        )  # fmt: skip
        if kind == "mention" and prior.get("kind") in ("fraud", "press", "intel"):
            kind = str(prior["kind"])
        published = doc.published_at
        facts = TextFacts(
            kind=kind,
            strong=any(hit.mode == "phrase" for hit in matches) or bool(prior.get("strong")),
            boosters=len({hit.term for hit in boosters} | set(prior.get("boosters") or [])),
            age_days=max((now - published).days, 0) if published else None,
            reprints=await documents.cluster_size(session, row.cluster_id),
        )
        score = score_text(facts)
        raw_llm = prior.get("llm")
        known = isinstance(raw_llm, dict) and raw_llm.get("verdict") in LLM_POINTS
        llm_prev = raw_llm if known else None
        if llm_prev is not None:
            score = with_llm(score, str(llm_prev["verdict"]))
        llm_cfg = await self.llm.cfg(session) if self.llm is not None and llm_prev is None else None
        wait = llm_cfg is not None and eligible(
            llm_cfg, category=score.category.value, score=score.value, strong=facts.strong
        )
        briefs = [
            documents.brief(row),
            *[old for old in prior.get("documents") or [] if old.get("id") != row.id],
        ][:20]
        match = {
            "kind": facts.kind,
            "strong": facts.strong,
            "document": documents.brief(row),
            "documents": briefs,
            "terms": sorted({hit.term for hit in matches} | set(prior.get("terms") or [])),
            "boosters": sorted({hit.term for hit in boosters} | set(prior.get("boosters") or [])),
            "contexts": list(dict.fromkeys([*contexts, *(prior.get("contexts") or [])]))[:10],
            "reprints": facts.reprints,
            "reasons": [{"reason": reason} for reason in text_reasons(facts)],
            **({"llm": llm_prev} if llm_prev is not None else {}),
        }
        up = await repo.upsert_finding(
            session,
            project_id=self.rules.project,
            entity=entity,
            score=score,
            match=match,
            source=item.connector_id,
            now=now,
        )
        await repo.add_observation(session, up.finding, item, score.value, now)
        result.findings.append(up.finding.id)
        alert_due = up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        )
        if wait:
            await adjudication.request(
                session, up.finding, hold=score.severity if alert_due else None, now=now
            )
        elif alert_due:
            alert = await repo.open_alert(session, up.finding, score.severity, now)
            result.alerts.append(alert.id)

    async def _repo_finding(
        self, session: AsyncSession, repo_name: str, now: datetime
    ) -> tuple[Entity, Finding | None]:
        entity = await repo.upsert_entity(session, "repo", repo_value(repo_name), now)
        previous = await session.scalar(
            select(Finding).where(
                Finding.project_id == self.rules.project, Finding.entity_id == entity.id
            )
        )
        return entity, previous

    async def _code_hit(self, session: AsyncSession, item: RawItem, result: ProcessResult) -> None:
        try:
            hit = parse_code_hit(item.payload["code_hit"])
        except ValueError as exc:
            log.warning("丢弃不合法的代码命中（%s）：%s", item.connector_id, exc)
            return
        now = self._clock()
        entity, previous = await self._repo_finding(session, hit["repo"], now)
        previous_match = previous.match if previous is not None else {}
        hits = merge_hits(previous_match.get("hits") or [], hit)
        await coderepos.touch(session, self.rules.project, hit["repo"], now)
        result.alerts += await self._score_repo(
            session,
            entity,
            hit["repo"],
            hits,
            previous_match.get("scan"),
            now=now,
            item=item,
            result=result,
            prior_llm=previous_match.get("llm_code"),
        )

    async def on_repo_scanned(
        self, session: AsyncSession, repo_name: str, data: dict[str, Any], now: datetime
    ) -> list[int]:
        """Merge only completed scans; skipped and failed scans preserve prior findings."""
        if not data.get("scanned"):
            return []
        entity, previous = await self._repo_finding(session, repo_name, now)
        previous_match = previous.match if previous is not None else {}
        scan = safe_scan(data, repo_name, now)
        return await self._score_repo(
            session,
            entity,
            repo_name,
            previous_match.get("hits") or [],
            scan,
            now=now,
            item=None,
            result=None,
            prior_llm=previous_match.get("llm_code"),
        )

    async def _score_repo(
        self,
        session: AsyncSession,
        entity: Entity,
        repo_name: str,
        hits: list[dict[str, Any]],
        scan: dict[str, Any] | None,
        *,
        now: datetime,
        item: RawItem | None,
        result: ProcessResult | None,
        prior_llm: Any = None,
    ) -> list[int]:
        facts = code_facts(hits, scan, now)
        score = score_code(facts)
        match: dict[str, Any] = {
            "repo": repo_name,
            "hits": hits,
            "scan": scan,
            "reasons": [{"reason": reason} for reason in code_reasons(facts)],
            "disclosure": disclosure_links(repo_name),
        }
        wait = False
        if score.category == Category.SECRET_LEAK:
            chosen = {str(s["fingerprint"]) for s in select_secrets(match)}
            judged = (prior_llm.get("secrets") if isinstance(prior_llm, dict) else None) or []
            verdicts = {
                str(x.get("fingerprint")): x.get("verdict") for x in judged if isinstance(x, dict)
            }
            if chosen and set(verdicts) == chosen:  # 密钥没变：沿用上次结论（研判开关关闭后也沿用）
                assert isinstance(prior_llm, dict)
                score = with_code_llm(
                    score,
                    summarize_secrets(str(v) for v in verdicts.values()),
                    str(prior_llm.get("relation")),
                )
                match["llm_code"] = prior_llm
            elif self.llm is not None:
                cfg = await self.llm.cfg(session)
                wait = cfg is not None and eligible_code(cfg, category=score.category.value)
        up = await repo.upsert_finding(
            session,
            project_id=self.rules.project,
            entity=entity,
            score=score,
            match=match,
            source=item.connector_id if item is not None else "secret_scan",
            now=now,
        )
        if item is not None:
            await repo.add_observation(session, up.finding, item, score.value, now)
        if result is not None:
            result.findings.append(up.finding.id)
        alert_due = up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        )
        if wait:
            await adjudication.request(
                session, up.finding, hold=score.severity if alert_due else None, now=now
            )
        elif alert_due:
            return [(await repo.open_alert(session, up.finding, score.severity, now)).id]
        return []

    async def _kev(self, session: AsyncSession, item: RawItem, result: ProcessResult) -> None:
        try:
            entry = parse_kev(item.payload)
        except KevError:
            log.warning("丢弃不合法的 KEV 条目（%s）", item.connector_id)
            return
        now = self._clock()
        row = await kev.upsert_entry(session, entry, now)
        result.alerts += await self._match_kev(session, row, now, item=item, result=result)

    async def rematch_kev(self, session: AsyncSession, row: KevEntry, now: datetime) -> list[int]:
        return await self._match_kev(session, row, now, item=None, result=None)

    async def _match_kev(
        self,
        session: AsyncSession,
        row: KevEntry,
        now: datetime,
        *,
        item: RawItem | None,
        result: ProcessResult | None,
    ) -> list[int]:
        if self.software is None:
            return []
        matches = self.software.match(row.vendor, row.product)
        if not matches:
            return []
        entity = await repo.upsert_entity(session, "cve", row.cve_id, now)
        if item is None:
            existing = await session.scalar(
                select(Finding.id).where(
                    Finding.project_id == self.rules.project, Finding.entity_id == entity.id
                )
            )
            if existing is not None:
                return []
        age = max((now.date() - row.date_added).days, 0)
        scored = [(VulnFacts(s.tier, s.exposed, row.ransomware, age), s) for s in matches]
        facts = max(scored, key=lambda pair: score_vulnerability(pair[0]).value)[0]
        score = score_vulnerability(facts)
        match = {
            "kev": kev.public_entry(row),
            "software": [
                {
                    "id": s.id,
                    "vendor": s.vendor,
                    "products": list(s.products),
                    "tier": s.tier,
                    "exposed": s.exposed,
                    "owner": s.owner,
                }
                for s in matches
            ],
            "reasons": [{"reason": r} for r in vuln_reasons(facts)],
        }
        up = await repo.upsert_finding(
            session, project_id=self.rules.project, entity=entity, score=score, match=match,
            source=item.connector_id if item is not None else "rematch", now=now,
        )  # fmt: skip
        if item is not None:
            await repo.add_observation(session, up.finding, item, score.value, now)
        if result is not None:
            result.findings.append(up.finding.id)
        if up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        ):
            return [(await repo.open_alert(session, up.finding, score.severity, now)).id]
        return []

    async def _leak_post(self, session: AsyncSession, item: RawItem, result: ProcessResult) -> None:
        try:
            post = parse_post(
                item.payload, allow_hosts=self._leak_link_hosts.get(item.connector_id)
            )
            if post.source != item.connector_id:
                raise LeakPostError("来源不一致")
        except LeakPostError:
            log.warning("丢弃不合法的泄露站帖子（%s）", item.connector_id)
            return
        now = self._clock()
        row = await leakposts.upsert_post(session, post, now)
        result.alerts += await self._match_leak_post(session, row, now, item=item, result=result)

    async def rematch_post(self, session: AsyncSession, row: LeakPost, now: datetime) -> list[int]:
        return await self._match_leak_post(session, row, now, item=None, result=None)

    async def _match_leak_post(
        self,
        session: AsyncSession,
        row: LeakPost,
        now: datetime,
        *,
        item: RawItem | None,
        result: ProcessResult | None,
    ) -> list[int]:
        if self._parties is None:
            return []
        matches = self._parties.match(row.victim, row.domain)
        if not matches:
            return []
        entity = await repo.upsert_entity(session, "leak_post", f"ransom:{row.key}", now)
        if item is None:
            existing = await session.scalar(
                select(Finding.id).where(
                    Finding.project_id == self.rules.project, Finding.entity_id == entity.id
                )
            )
            if existing is not None:
                return []
        age = max((now - row.discovered).days, 0)
        scored = [
            (
                score_ransomware(
                    RansomFacts("self" if m.party.kind == "self" else m.party.tier, m.how, age)
                ),
                m,
            )
            for m in matches
        ]
        score = max(scored, key=lambda pair: pair[0].value)[0]
        match = {
            "post": leakposts.public_post(row),
            "parties": [
                {
                    "kind": m.party.kind,
                    "id": m.party.id,
                    "name": m.party.name,
                    "tier": m.party.tier,
                    "owner": m.party.owner,
                    "how": m.how,
                    "detail": m.detail,
                }
                for m in matches
            ],
            "reasons": [{"reason": r} for r in ransomware_reasons(matches)],
        }
        up = await repo.upsert_finding(
            session,
            project_id=self.rules.project,
            entity=entity,
            score=score,
            match=match,
            source=item.connector_id if item is not None else "rematch",
            now=now,
        )
        if item is not None:
            await repo.add_observation(session, up.finding, item, score.value, now)
        if result is not None:
            result.findings.append(up.finding.id)
        if up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        ):
            return [(await repo.open_alert(session, up.finding, score.severity, now)).id]
        return []

    async def _exposure(self, session: AsyncSession, item: RawItem, result: ProcessResult) -> None:
        try:
            ex = parse_exposure(item.payload["exposure"], self.rules.domains.official)
        except ExposureError:
            log.warning("丢弃不合法的暴露载荷（%s）", item.connector_id)
            return
        now = self._clock()
        entity = await repo.upsert_entity(session, "breach", ex.key, now)
        previous = await session.scalar(
            select(Finding).where(
                Finding.project_id == self.rules.project, Finding.entity_id == entity.id
            )
        )
        known = 0
        if previous is not None:
            known = max(
                int((previous.match.get("exposure") or {}).get("affected") or 0),
                int(
                    await session.scalar(
                        select(func.count())
                        .select_from(ExposedAccount)
                        .where(ExposedAccount.finding_id == previous.id)
                    )
                    or 0
                ),
            )
        affected = max(ex.affected, len(ex.accounts), known)
        public = {**ex.public(), "affected": affected}
        if not ex.data_classes and previous is not None:
            old = previous.match.get("exposure") or {}
            for key in (
                "title",
                "breach_date",
                "added_date",
                "data_classes",
                "verified",
                "fabricated",
                "sensitive",
                "spam_list",
                "stealer_log",
            ):
                if key in old and old[key] not in (None, [], ""):
                    public[key] = old[key]
        breach_date = public.get("breach_date")
        try:
            age_days = (
                max(0, (now.date() - date.fromisoformat(breach_date)).days) if breach_date else None
            )
        except (TypeError, ValueError):
            age_days = None
        facts = replace(
            ex.facts(now),
            affected=affected,
            data_classes=frozenset(public.get("data_classes") or []),
            age_days=age_days,
            verified=bool(public.get("verified")),
            fabricated=bool(public.get("fabricated")),
            spam_list=bool(public.get("spam_list")),
        )
        score = score_exposure(facts)
        match = {"exposure": public, "reasons": [{"reason": r} for r in exposure_reasons(facts)]}
        up = await repo.upsert_finding(
            session, project_id=self.rules.project, entity=entity, score=score, match=match,
            source=item.connector_id, now=now,
        )  # fmt: skip
        if ex.accounts:
            stmt = pg_insert(ExposedAccount).values(
                [
                    {"project_id": self.rules.project, "finding_id": up.finding.id, "email": email,
                     "source": item.connector_id, "first_seen": now, "last_seen": now}
                    for email in ex.accounts
                ]
            )  # fmt: skip
            await session.execute(
                stmt.on_conflict_do_update(
                    constraint="uq_exposed_account_finding_id",
                    set_={"last_seen": stmt.excluded.last_seen},
                )
            )
        await repo.add_observation(session, up.finding, item, score.value, now)
        result.findings.append(up.finding.id)
        if up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        ):
            alert = await repo.open_alert(session, up.finding, score.severity, now)
            result.alerts.append(alert.id)

    async def _suppressed(self, session: AsyncSession, domain: str, registered: str) -> bool:
        return (
            await suppression.find_active(
                session, self.rules.project, domain=domain, registered=registered, now=self._clock()
            )
            is not None
        )

    async def _feed_url(self, session: AsyncSession, item: RawItem, result: ProcessResult) -> None:
        raw = str(item.payload["feed_url"])
        # Preserve only matched brand segments from removed userinfo, never a
        # password. Re-match the input and check that its target is unchanged.
        context = item.payload.get("match_input")
        if isinstance(context, str) and normalize_url(context) == normalize_url(raw):
            raw = context
        um = self._url_matcher.match(raw)
        if um is None or um.kind is None:
            return
        if await self._suppressed(session, um.host, um.registered):
            result.suppressed.append(um.url)
            return
        intel_data = item.payload.get("intel")
        intel = isinstance(intel_data, dict) and intel_data.get("confirmed") is True
        if um.kind == "domain":
            assert um.host_match is not None
            await self._brand_domain(session, item, um.host_match, result, intel=intel, url=um.url)
        else:
            await self._brand_url(session, item, um, result, intel=intel)

    async def _brand_url(
        self,
        session: AsyncSession,
        item: RawItem,
        um: UrlMatch,
        result: ProcessResult,
        *,
        intel: bool,
        signal: str | None = None,
    ) -> None:
        now = self._clock()
        entity = await repo.upsert_entity(session, "url", um.url, now)
        # A path-only phishing URL still needs host-level DNS/RDAP evidence.
        # Keep the URL as the entity so shared hosts are never treated as
        # lookalike domains; cache host enrichments with an explicit target.
        host_targets = {eid: ("domain", um.host) for eid in ("dns", "rdap", "tranco")}
        enrichment = await self.enrichment.enrich(entity, self._enrich_ids, targets=host_targets)
        score = score_url(build_url_signals(um, enrichment, intel_hit=True if intel else None))
        match = um.to_dict()
        score, match = await self._owned_score(session, entity, item, score, match, signal)
        up = await repo.upsert_finding(
            session,
            project_id=self.rules.project,
            entity=entity,
            score=score,
            match=match,
            source=item.connector_id,
            now=now,
        )
        await repo.add_observation(session, up.finding, item, score.value, now)
        result.findings.append(up.finding.id)
        if up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        ):
            alert = await repo.open_alert(session, up.finding, score.severity, now)
            result.alerts.append(alert.id)

    async def _brand_domain(
        self,
        session: AsyncSession,
        item: RawItem,
        m: DomainMatch,
        result: ProcessResult,
        *,
        intel: bool = False,
        url: str | None = None,
        signal: str | None = None,
    ) -> None:
        now = self._clock()
        entity = await repo.upsert_entity(session, "domain", m.domain, now)
        targets = {"http_probe": ("url", url)} if url is not None else None
        enrichment = await self.enrichment.enrich(entity, self._enrich_ids, targets=targets)
        score = score_domain(
            build_domain_signals(m, enrichment, now=now, intel_hit=True if intel else None)
        )
        match = m.to_dict() if url is None else {**m.to_dict(), "url": url}
        botnet = enrichment.get("botnet_feed") or {}
        if botnet.get("feodo") or botnet.get("sslbl"):
            match["botnet_context"] = {
                "feodo": botnet.get("feodo") or [],
                "sslbl": botnet.get("sslbl"),
            }
        score, match = await self._owned_score(session, entity, item, score, match, signal)
        up = await repo.upsert_finding(
            session,
            project_id=self.rules.project,
            entity=entity,
            score=score,
            match=match,
            source=item.connector_id,
            now=now,
        )
        await repo.add_observation(session, up.finding, item, score.value, now)
        result.findings.append(up.finding.id)
        if up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        ):
            alert = await repo.open_alert(session, up.finding, score.severity, now)
            result.alerts.append(alert.id)
        if signal in WATCH_SIGNALS or (
            score.category == Category.TYPOSQUAT_DOMAIN
            and score.value < policy.current().watchlist.watch_below_score
        ):
            reason = f"{item.connector_id}: score={score.value}"
            if await watchlist.ensure_watched(
                session, self.rules.project, m.domain, reason=reason, now=now
            ):
                result.watched.append(m.domain)

    @staticmethod
    def _context(item: RawItem, *, contact: bool = False) -> dict[str, Any]:
        context = dict(item.payload.get("context") or {})
        if item.connector_id == "public_report" and not contact:
            context.pop("contact", None)
        return context

    async def _owned_score(
        self,
        session: AsyncSession,
        entity: Entity,
        item: RawItem,
        score: Score,
        match: dict[str, Any],
        signal: str | None,
    ) -> tuple[Score, dict[str, Any]]:
        previous = await session.scalar(
            select(Finding).where(
                Finding.project_id == self.rules.project, Finding.entity_id == entity.id
            )
        )
        if signal:
            match = {**match, "signal": signal, "context": self._context(item)}
        elif previous is not None and previous.match.get("signal") in SIGNALS:
            signal = str(previous.match["signal"])
            match = {**match, "signal": signal, "context": previous.match.get("context", {})}
        if signal:
            # A later owned observation must not erase an earlier confirmed feed.
            if previous is not None and previous.score_breakdown.get("intel_hits") == 20:
                breakdown = {**score.breakdown, "base": 40, "intel_hits": 20}
                value = max(0, min(100, sum(breakdown.values())))
                score = Score(value, severity_for(value), Category.PHISHING_SITE, breakdown)
            if previous is not None and previous.match.get("signal") in SIGNALS:
                old_signal = str(previous.match["signal"])
                if SIGNAL_POINTS[old_signal] > SIGNAL_POINTS[signal]:
                    signal = old_signal
                    match["signal"] = signal
            score = with_signal(score, signal)
        return score, match

    async def _indicators(
        self, session: AsyncSession, item: RawItem, result: ProcessResult
    ) -> None:
        """机构自有数据（举报、金丝雀、盗链、DMARC）：命中品牌的并入原流程，不命中的按信号建 Finding。"""
        signal = str(item.payload.get("signal") or "")
        if signal not in SIGNALS:
            return
        intel_data = item.payload.get("intel")
        intel = (
            isinstance(intel_data, dict)
            and intel_data.get("confirmed") is True
            and signal != "canary"
        )
        seen: set[tuple[str, str]] = set()
        processed: set[tuple[str, str]] = set()
        for ind in list(item.payload["indicators"])[:MAX_INDICATORS]:
            if not isinstance(ind, dict):
                continue
            kind, value = str(ind.get("type") or ""), str(ind.get("value") or "")
            try:
                volume = max(0, int(ind.get("volume") or 0))
            except (ValueError, TypeError, OverflowError):
                continue
            if not value:
                continue
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
            if kind == "ip":
                await self._signal_ip(session, item, value, signal, volume, intel, result)
            elif kind == "report":
                await self._signal_entity(
                    session, item, "report", value[:100], signal, volume, intel, result
                )
            elif kind in ("url", "domain"):
                if kind == "domain" and parse_domain(value) is None:
                    continue
                um = self._url_matcher.match(value if kind == "url" else f"http://{value}/")
                if um is None or (um.host_match is not None and um.host_match.status != "match"):
                    continue  # 无效地址、官方资产、已知合法相似方
                try:
                    if not ipaddress.ip_address(um.host).is_global:
                        continue
                except ValueError:
                    pass
                target = (
                    ("domain", um.host)
                    if um.kind == "domain" or kind == "domain"
                    else ("url", um.url)
                )
                if target in processed:
                    continue
                processed.add(target)
                if await self._suppressed(session, um.host, um.registered):
                    result.suppressed.append(um.url if kind == "url" else um.host)
                    continue
                if um.kind == "domain":
                    assert um.host_match is not None
                    url = um.url if kind == "url" else None
                    await self._brand_domain(
                        session, item, um.host_match, result, intel=intel, url=url, signal=signal
                    )
                elif um.kind == "url":
                    await self._brand_url(session, item, um, result, intel=intel, signal=signal)
                elif kind == "url":
                    await self._signal_entity(
                        session, item, "url", um.url, signal, volume, intel, result
                    )
                else:
                    await self._signal_entity(
                        session, item, "domain", um.host, signal, volume, intel, result
                    )

    async def _signal_ip(
        self, session: AsyncSession, item: RawItem, value: str, signal: str, volume: int,
        intel: bool, result: ProcessResult,
    ) -> None:  # fmt: skip
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return
        if not ip.is_global:
            return  # 内网地址不是冒用来源（多为转发链路），不建 Finding
        await self._signal_entity(session, item, "ip", str(ip), signal, volume, intel, result)

    async def _signal_entity(
        self, session: AsyncSession, item: RawItem, entity_type: str, value: str, signal: str,
        volume: int, intel: bool, result: ProcessResult,
    ) -> None:  # fmt: skip
        now = self._clock()
        entity = await repo.upsert_entity(session, entity_type, value, now)
        enrichment = (
            await self.enrichment.enrich(entity, self._enrich_ids)
            if entity_type in ("url", "domain", "ip")
            else {}
        )
        http = enrichment.get("http_probe") or {}
        status = http.get("status")
        page_ok = http.get("reachable") is True and isinstance(status, int) and status < 400
        brand = bool(http.get("brand_terms")) if page_ok else None
        if entity_type == "report":  # 公众举报：入口程序已检查描述中是否提到本机构品牌
            brand = bool((item.payload.get("context") or {}).get("brand_mentioned"))
        score = score_signal(
            SignalFacts(
                signal=signal,
                volume=volume,
                intel_hit=intel,
                has_login_form=bool(http.get("has_password_field")) if page_ok else None,
                brand_in_content=brand,
            )
        )
        match = {
            "signal": signal,
            "indicator": {"type": entity_type, "value": value, "volume": volume},
            "context": self._context(item, contact=entity_type == "report"),
            "reasons": [{"reason": signal}],
        }
        up = await repo.upsert_finding(
            session, project_id=self.rules.project, entity=entity, score=score, match=match,
            source=item.connector_id, now=now,
        )  # fmt: skip
        await repo.add_observation(session, up.finding, item, score.value, now)
        result.findings.append(up.finding.id)
        if up.escalated and severity_rank(score.severity) >= severity_rank(
            policy.current().risk.alert_from
        ):
            alert = await repo.open_alert(session, up.finding, score.severity, now)
            result.alerts.append(alert.id)
        if entity_type == "domain" and signal in WATCH_SIGNALS and parse_domain(value) is not None:
            reason = f"{item.connector_id}: {signal}"
            if await watchlist.ensure_watched(
                session, self.rules.project, value, reason=reason, now=now
            ):
                result.watched.append(value)

    async def _own_certificate(
        self, session: AsyncSession, item: RawItem, m: DomainMatch, result: ProcessResult
    ) -> None:
        now = self._clock()
        entity = await repo.upsert_entity(session, "domain", m.domain, now)
        score = score_own_domain_cert(item.payload.get("issuer_approved"))
        if score is None:
            return
        cert = item.payload.get("cert") or {}
        up = await repo.upsert_finding(
            session,
            project_id=self.rules.project,
            entity=entity,
            score=score,
            match={
                **m.to_dict(),
                "issuer_o": cert.get("issuer_o"),
                "certificate": {
                    key: cert[key] for key in ("sha256", "not_after", "issuer_o") if key in cert
                },
            },
            source=item.connector_id,
            now=now,
        )
        await repo.add_observation(session, up.finding, item, score.value, now)
        result.findings.append(up.finding.id)
        if up.escalated:
            alert = await repo.open_alert(session, up.finding, score.severity, now)
            result.alerts.append(alert.id)

    async def on_watch_change(
        self, session: AsyncSession, wd: WatchedDomain, changes: list[str]
    ) -> None:
        """监视列表发现变化时，用最新（刚强制刷新过的）富化结果重新评分。"""
        now: datetime = self._clock()
        item = RawItem(
            connector_id="watchlist",
            source_item_id=f"{wd.domain}@{now.isoformat()}",
            fetched_at=now,
            url=None,
            payload={"domain": wd.domain, "changes": changes, "matches": [{"domain": wd.domain}]},
            project_ids=(wd.project_id,),
        )
        finding = await session.scalar(
            select(Finding)
            .join(Entity)
            .where(
                Finding.project_id == wd.project_id,
                Entity.type == "domain",
                Entity.value == wd.domain,
            )
        )
        if finding is not None and finding.match.get("signal") in WATCH_SIGNALS:
            item = replace(
                item,
                payload={
                    "indicators": [
                        {
                            "type": "domain",
                            "value": wd.domain,
                            "volume": (finding.match.get("indicator") or {}).get("volume", 0),
                        }
                    ],
                    "signal": finding.match["signal"],
                    "context": finding.match.get("context", {}),
                },
            )
        # WatchedDomain 已由 Project 外键约束；此时事务持有 Entity/WatchedDomain 锁，
        # 不可再回头更新 Project，否则配置恰好变化时仍会形成反向锁顺序。
        await self.process(session, item, sync_project=False)
