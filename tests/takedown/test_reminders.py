from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.takedown import service
from opti.takedown.config import TakedownConfig
from opti.takedown.render import Material
from opti.takedown.service import Actor
from opti.takedown.targets import Target

pytestmark = pytest.mark.db
CFG = TakedownConfig.model_validate(
    {
        "max_reminders": 2,
        "escalation": [{"kind": "registrar", "name": "Registry Compliance", "channel": {"url": "https://compliance.example/"}}],
    }
)  # fmt: skip
TARGET = Target("registrar", "registrar:cheap", "Cheap Registrar LLC", "abuse@registrar.example", None, "rdap_registrar")  # fmt: skip
REPORT = Target(
    "report", "report:browser", "Browser Blocklist", None, "https://report.example/", "reporting"
)


async def _submitted(
    session: AsyncSession, seed: Callable[..., Awaitable[Any]], make_user: Callable[[str], Awaitable[int]],
    target: Target, now: datetime, domain: str = "sbr-loans.com",
) -> Any:  # fmt: skip
    s = await seed(domain)
    alice, bob = await make_user(f"a-{domain}"), await make_user(f"b-{domain}")
    td = await service.create(
        session, project_id=s.alert.project_id, alert_id=s.alert.id, finding_id=s.finding.id, host=domain,
        target=target, material=Material("s", "b\n"), language="en-US", actor=Actor(alice, "a"), now=now,
    )  # fmt: skip
    await service.transition(session, td, "approved", actor=Actor(bob, "b"), now=now, cfg=CFG)
    await service.transition(session, td, "submitted", actor=Actor(alice, "a"), now=now, cfg=CFG)
    return td


async def test_overdue_and_reminder_cycle(
    session: AsyncSession,
    seed: Callable[..., Awaitable[Any]],
    make_user: Callable[[str], Awaitable[int]],
) -> None:
    t0 = datetime.now(UTC) - timedelta(days=10)
    td = await _submitted(session, seed, make_user, TARGET, t0)
    report = await _submitted(session, seed, make_user, REPORT, t0, "sbr-credit.com")
    assert report.due_at is None  # 举报渠道不跟踪 SLA
    assert await service.overdue(session, t0 + timedelta(hours=71), limit=10) == []
    t1 = t0 + timedelta(hours=73)
    assert await service.overdue(session, t1, limit=10) == [td]

    notice = service.reminder_notice(CFG, td, "https://ti.example/")
    assert notice.title == f"下架投诉 #{td.id} 超过 SLA 未处理"
    facts = dict(notice.facts)
    assert facts["域名"] == "sbr-loans[.]com" and facts["已提醒次数"] == "1"
    assert "Registry Compliance https://compliance.example/" in facts["建议升级"]
    assert notice.link == f"https://ti.example/takedowns?id={td.id}"

    await service.mark_reminded(session, td, CFG, t1)
    assert td.reminders == 1 and td.due_at == t1 + timedelta(hours=72)
    t2 = t1 + timedelta(hours=73)
    await service.mark_reminded(session, td, CFG, t2)
    assert td.reminders == 2 and td.due_at is None  # 达到 max_reminders 后不再提醒
    assert await service.overdue(session, t2 + timedelta(days=30), limit=10) == []
