from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy import select

from opti.db.models import AuditLog

pytestmark = pytest.mark.db
UserFactory = Callable[..., Awaitable[int]]
RULES = Path(__file__).resolve().parents[2] / "config" / "projects" / "sample-brand" / "keywords.yaml"


async def test_current_rules(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user()
    c = await login()
    r = await c.post(
        "/api/v1/rules/test",
        json={"domains": ["sbr-loans.com", "sbrbank.com", "example.org", "  "],
              "text": "Sample Brand 提供低息贷款，请先交手续费"},
    )  # fmt: skip
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "current" and body["project"] == "sample-brand-protection"
    assert [d["status"] for d in body["domains"]] == ["match", "known_lookalike", "no_match"]
    assert body["domains"][0]["score"]["value"] > 0
    terms = {(h["term"], h["role"]) for h in body["text_hits"]}
    assert ("Sample Brand", "match") in terms and ("低息贷款", "booster") in terms


async def test_draft_is_used_but_not_saved(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user()
    c = await login()
    draft = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    draft["domains"]["brand_tokens"].append("orbitdev")
    text = yaml.safe_dump(draft, allow_unicode=True)
    with_draft = (
        await c.post(
            "/api/v1/rules/test", json={"domains": ["orbitdev-loans.com"], "draft_yaml": text}
        )
    ).json()
    assert with_draft["source"] == "draft" and with_draft["domains"][0]["status"] == "match"
    current = (await c.post("/api/v1/rules/test", json={"domains": ["orbitdev-loans.com"]})).json()
    assert current["domains"][0]["status"] == "no_match"


async def test_invalid_draft_reports_reason(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user()
    c = await login()
    r = await c.post("/api/v1/rules/test", json={"draft_yaml": "project: x\n"})
    assert r.status_code == 422 and "校验失败" in r.json()["detail"]["message"]


async def test_draft_with_yaml_aliases_is_rejected(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    c = await login()
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: [*c, *c]\n"
    r = await c.post("/api/v1/rules/test", json={"draft_yaml": bomb})
    assert r.status_code == 422 and "别名" in r.json()["detail"]["message"]
    assert (
        await c.post("/api/v1/rules/test", json={"draft_yaml": "x" * 200_001})
    ).status_code == 422
    assert (
        await c.post("/api/v1/rules/test", json={"domains": ["a.com"] * 201})
    ).status_code == 422


async def test_rules_test_audit_records_only_hash(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    await make_user()
    c = await login()
    draft = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    draft["sets"]["brand"]["terms"].append({"value": "Secret Project Falcon", "mode": "phrase"})
    await c.post(
        "/api/v1/rules/test",
        json={"text": "x", "draft_yaml": yaml.safe_dump(draft, allow_unicode=True)},
    )
    async with api.sessions() as s:
        row = (await s.scalars(select(AuditLog).where(AuditLog.action == "rules.test"))).one()
    assert row.detail["source"] == "draft" and len(row.detail["draft_sha256"]) == 64
    assert "Falcon" not in str(row.detail)


async def test_rules_test_permissions(api: Any, make_user: UserFactory, login: Any) -> None:
    await make_user("vic", roles=("viewer",))
    await make_user("cora", roles=("compliance_officer",))
    assert (
        await (await login("vic")).post("/api/v1/rules/test", json={"text": "x"})
    ).status_code == 403
    assert (
        await (await login("cora")).post("/api/v1/rules/test", json={"text": "x"})
    ).status_code == 200


async def test_anchor_and_oversized_domain_are_rejected(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user()
    c = await login()
    r = await c.post("/api/v1/rules/test", json={"draft_yaml": "project: &p sbr\n"})
    assert r.status_code == 422 and "锚点" in r.text
    assert (await c.post("/api/v1/rules/test", json={"domains": ["x" * 254]})).status_code == 422


async def test_deeply_nested_draft_is_rejected(api: Any, make_user: Any, login: Any) -> None:
    await make_user()
    c = await login()
    draft = "project: " + "[" * 100 + "x" + "]" * 100
    r = await c.post("/api/v1/rules/test", json={"draft_yaml": draft})
    assert r.status_code == 422 and "结构过深" in r.text
