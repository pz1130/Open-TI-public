"""Analyst-initiated translation of stored alert snippets, never full source text."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import TranslationIn, TranslationOut
from opti.db.models import Alert, AlertFinding, Finding
from opti.translation import TranslationError

router = APIRouter(tags=["translation"])
Reader = Annotated[Principal, Depends(require(Perm.EVIDENCE_READ))]
_LANGUAGE = re.compile(r"[a-z]{2}\Z")


def _source(match: dict[str, Any]) -> tuple[str, str, list[str]]:
    brief = match.get("document")
    if not isinstance(brief, dict):
        raise HTTPException(404, "document alert not found")
    raw_language = brief.get("language")
    language = str(raw_language or "").lower().split("-")[0]
    if not _LANGUAGE.fullmatch(language):
        raise HTTPException(409, "document language is unknown")
    raw_title = brief.get("title")
    title = raw_title[:500] if isinstance(raw_title, str) else ""
    raw_contexts = match.get("contexts")
    contexts = (
        [value[:300] for value in raw_contexts if isinstance(value, str) and value.strip()][:10]
        if isinstance(raw_contexts, list)
        else []
    )
    if not title and not contexts:
        raise HTTPException(409, "no stored text to translate")
    return language, title, contexts


@router.post("/alerts/{alert_id}/translation")
async def translate_alert(
    alert_id: int, body: TranslationIn, request: Request, user: Reader
) -> TranslationOut:
    deps = get_deps(request)
    if Perm.ALERTS_READ not in user.perms:
        raise HTTPException(403, "forbidden")
    translator = deps.translator
    if translator is None:
        raise HTTPException(503, "local translation is not configured")
    async with deps.sessions.begin() as session:
        finding = await session.scalar(
            select(Finding)
            .join(AlertFinding, AlertFinding.finding_id == Finding.id)
            .join(Alert, Alert.id == AlertFinding.alert_id)
            .where(
                Alert.id == alert_id,
                Alert.project_id == deps.rules.project,
                Finding.project_id == deps.rules.project,
            )
        )
        if finding is None or finding.category not in {
            "brand_mention",
            "negative_press",
            "fraud_scam",
            "threat_intel",
        }:
            raise HTTPException(404, "document alert not found")
        source, title, contexts = _source(finding.match or {})
        target = body.target_language
        if source == target:
            raise HTTPException(409, "document is already in target language")
        retry_after = deps.translation_requests.retry_after(str(user.user_id), deps.clock())
        if retry_after is not None:
            raise HTTPException(
                429, "translation rate limit reached", headers={"Retry-After": str(retry_after)}
            )
        deps.translation_requests.hit(str(user.user_id), deps.clock())
        await record(
            session,
            request,
            user,
            "document.translate",
            target_type="alert",
            target_id=alert_id,
            detail={
                "source": source,
                "target": target,
                "chars": len(title) + sum(map(len, contexts)),
            },
        )
    texts = ([title] if title else []) + contexts
    try:
        translated = await translator.translate(texts, source=source, target=target)
    except (TranslationError, ValueError) as exc:
        raise HTTPException(502, "local translation failed") from exc
    return TranslationOut(
        source_language=source,
        target_language=target,
        title=translated[0] if title else "",
        contexts=translated[1:] if title else translated,
    )
