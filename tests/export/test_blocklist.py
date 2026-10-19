from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.domains import to_ascii
from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.export.blocklist import confirmed_entries, to_csv, to_rpz, to_txt
from opti.pipeline import suppression

pytestmark = pytest.mark.db


async def _judged(
    session: AsyncSession, rules: ProjectRules, value: str, verdict: str = "true_positive",
    *, entity_type: str = "domain", now: datetime,
) -> None:  # fmt: skip
    await repo.upsert_project(session, rules)
    e = await repo.upsert_entity(session, entity_type, value, now)
    up = await repo.upsert_finding(
        session, project_id=rules.project, entity=e,
        score=Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 70}),
        match={}, source="test", now=now,
    )  # fmt: skip
    alert = await repo.open_alert(session, up.finding, Severity.HIGH, now)
    alert.triage_verdict = verdict
    await session.flush()


async def test_blocklist_exclusions_and_idn(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    now = datetime.now(UTC)
    official = sbr_rules.domains.official[0]
    known = sbr_rules.domains.known_lookalikes[0]
    await _judged(session, sbr_rules, "sbr-loans.com", now=now)
    await _judged(session, sbr_rules, "sbr-bänk.com", now=now)
    await _judged(session, sbr_rules, f"login.{official}", now=now)  # 官方域名的子域
    await _judged(session, sbr_rules, known, now=now)  # 已知合法相似方
    await _judged(session, sbr_rules, "sbr-pay.top", "false_positive", now=now)
    await _judged(session, sbr_rules, "sbr-credit.com", now=now)
    await _judged(session, sbr_rules, "sbr-credit.com", "false_positive", now=now)  # 后来改判为误报
    await _judged(session, sbr_rules, "sbr-wallet.com", now=now)
    await suppression.create_rule(
        session, project_id=sbr_rules.project, kind="registered_domain", value="sbr-wallet.com",
        reason="vendor", now=now,
    )  # fmt: skip
    await _judged(session, sbr_rules, "sbr-old.com", now=now - timedelta(days=200))  # 超出时间窗
    url = "https://storage.example.net/sbr/login.html"
    await _judged(session, sbr_rules, url, entity_type="url", now=now)

    entries = await confirmed_entries(session, sbr_rules, now=now, days=180)
    assert sorted(e.value for e in entries) == sorted(["sbr-loans.com", "sbr-bänk.com", url])

    rpz = to_rpz(entries, now)
    assert rpz.startswith("$TTL 300\n") and f"({int(now.timestamp())} " in rpz
    assert "sbr-loans.com CNAME .\n*.sbr-loans.com CNAME .\n" in rpz
    assert f"{to_ascii('sbr-bänk.com')} CNAME ." in rpz and "ä" not in rpz
    assert "storage.example.net" not in rpz  # 共享托管：URL 的主机绝不进入 RPZ
    assert to_txt(entries) == "".join(sorted(["sbr-loans.com\n", f"{to_ascii('sbr-bänk.com')}\n"]))
    assert to_txt(entries, "url") == f"{url}\n"
    lines = to_csv(entries).splitlines()
    assert lines[0] == "type,value,category,severity,first_seen,last_seen,alert_id"
    assert len(lines) == 4 and any(url in line for line in lines)


def test_rpz_rejects_zone_injection_and_csv_normalizes_idn():
    from opti.export.blocklist import Entry

    now = datetime.now(UTC)
    rows = [
        Entry("domain", "bad.example\n* CNAME .", "phishing_site", "high", now, now, 1),
        Entry("domain", "bänk.example", "phishing_site", "high", now, now, 2),
    ]
    assert "bad.example" not in to_rpz(rows, now)
    assert "xn--bnk-qla.example" in to_csv(rows)
