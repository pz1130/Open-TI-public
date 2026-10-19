from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from opti.api.throttle import SlidingWindow
from opti.configs.runtime import ConfigRuntime
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import AuditLog, Finding
from opti.translation import TranslationError

pytestmark = pytest.mark.db


class FakeTranslator:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[list[str], str, str]] = []
        self.fail = fail

    async def translate(self, texts: list[str], *, source: str, target: str) -> list[str]:
        self.calls.append((texts, source, target))
        if self.fail:
            raise TranslationError("unavailable")
        return [f"译：{value}" for value in texts]


async def _seed(api: Any, *, project: str | None = None, language: str | None = "en") -> int:
    rules = api.rules if project is None else api.rules.model_copy(update={"project": project})
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, rules)
        entity = await repo.upsert_entity(s, "document", f"cluster:{rules.project}", api.clock())
        finding = await repo.upsert_finding(
            s,
            project_id=rules.project,
            entity=entity,
            score=Score(70, Severity.HIGH, Category.FRAUD_SCAM, {"base": 40, "boosters": 30}),
            match={
                "document": {"id": 9, "title": "Bank approves loan", "language": language},
                "contexts": ["Sample Brand approved a loan"],
            },
            source="rss",
            now=api.clock(),
        )
        alert = await repo.open_alert(s, finding.finding, Severity.HIGH, api.clock())
        return alert.id


async def test_translation_is_scoped_audited_and_not_persisted(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("alice", ("analyst",))
    await make_user("viewer", ("viewer",))
    alert_id = await _seed(api)
    other_id = await _seed(api, project="other-project")
    translator = FakeTranslator()
    api.app.state.deps.translator = translator
    analyst = await login("alice")
    detail = (await analyst.get(f"/api/v1/alerts/{alert_id}")).json()
    assert detail["translation_available"] is True
    result = await analyst.post(
        f"/api/v1/alerts/{alert_id}/translation", json={"target_language": "zh"}
    )
    assert result.status_code == 200, result.text
    assert result.json() == {
        "source_language": "en",
        "target_language": "zh",
        "title": "译：Bank approves loan",
        "contexts": ["译：Sample Brand approved a loan"],
    }
    assert translator.calls == [
        (["Bank approves loan", "Sample Brand approved a loan"], "en", "zh")
    ]
    async with api.sessions() as s:
        audit = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "document.translate"))
        ).one()
        assert audit.detail == {"source": "en", "target": "zh", "chars": 46}
        finding = (
            await s.scalars(select(Finding).where(Finding.project_id == api.rules.project))
        ).one()
        assert finding.match["document"]["title"] == "Bank approves loan"
        assert "译：" not in str(finding.match)
    assert (
        await analyst.post(f"/api/v1/alerts/{other_id}/translation", json={"target_language": "zh"})
    ).status_code == 404
    assert (
        await (await login("viewer")).post(
            f"/api/v1/alerts/{alert_id}/translation", json={"target_language": "zh"}
        )
    ).status_code == 403


async def test_translation_disabled_unknown_language_failure_and_limit(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    alert_id = await _seed(api)
    analyst = await login()
    endpoint = f"/api/v1/alerts/{alert_id}/translation"
    assert (await analyst.post(endpoint, json={"target_language": "zh"})).status_code == 503
    translator = FakeTranslator(fail=True)
    api.app.state.deps.translator = translator
    assert (await analyst.post(endpoint, json={"target_language": "en"})).status_code == 409
    assert (await analyst.post(endpoint, json={"target_language": "zh"})).status_code == 502
    api.app.state.deps.translation_requests = SlidingWindow(1, timedelta(minutes=1))
    assert (await analyst.post(endpoint, json={"target_language": "zh"})).status_code == 502
    throttled = await analyst.post(endpoint, json={"target_language": "zh"})
    assert throttled.status_code == 429 and int(throttled.headers["Retry-After"]) > 0
    assert len(translator.calls) == 2

    unknown = await _seed(api, project="unknown-doc", language=None)
    # Switch the test project to exercise an in-scope alert with missing language.
    deps = api.app.state.deps
    deps.config = ConfigRuntime.static(
        api.rules.model_copy(update={"project": "unknown-doc"}),
        deps.organization,
        sessions=deps.sessions,
    )
    assert (
        await analyst.post(f"/api/v1/alerts/{unknown}/translation", json={"target_language": "zh"})
    ).status_code == 409
