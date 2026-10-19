import pytest

from opti.db import audit
from opti.db.models import KevEntry
from opti.pipeline import tasks
from tests.api.conftest import ApiWorld

pytestmark = pytest.mark.db


async def test_vendor_save_queues_rematch(
    api: ApiWorld, make_user, login, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    queued: list[str] = []

    async def enqueue() -> None:
        queued.append("vendors")

    monkeypatch.setattr(tasks.rematch_leak_posts, "kiq", enqueue)
    await make_user("ops", ("platform_admin",))
    client = await login("ops")
    assert (await client.get("/api/v1/config/vendors/rematch")).json()["status"] == "none"
    response = await client.put(
        "/api/v1/config/vendors",
        json={
            "data": {
                "vendors": [{"id": "acme", "name": "Acme Cloud", "domains": ["acme.example"]}]
            },
            "base_version": 0,
        },
    )
    assert response.status_code == 200, response.text
    assert queued == ["vendors"]
    state = (await client.get("/api/v1/config/vendors/rematch")).json()
    assert state["status"] == "queued" and state["version"] == 1
    async with api.sessions.begin() as session:
        await audit.append(
            session,
            actor="system:rematch",
            action="config.rematched",
            now=api.clock(),
            target_type="config",
            target_id="vendors",
            detail={"kind": "vendors", "version": 1, "alerts": 2},
        )
    done = (await client.get("/api/v1/config/vendors/rematch")).json()
    assert done["status"] == "done" and done["alerts"] == 2
    assert (await client.get("/api/v1/config/retention/rematch")).status_code == 404


async def test_kev_products(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    async with api.sessions.begin() as session:
        for cve, product in (("CVE-2026-1", "FortiOS"), ("CVE-2026-2", "FortiProxy")):
            now = api.clock()
            session.add(
                KevEntry(
                    cve_id=cve,
                    vendor="Fortinet",
                    product=product,
                    date_added=now.date(),
                    due_date=None,
                    first_seen=now,
                    last_seen=now,
                )
            )
    await make_user("vic", ("viewer",))
    client = await login("vic")
    response = await client.get(
        "/api/v1/config/software/kev-products", params={"vendor": "fortinet"}
    )
    assert response.json() == ["FortiOS", "FortiProxy"]
