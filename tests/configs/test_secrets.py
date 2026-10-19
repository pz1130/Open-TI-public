from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from opti.configs import secrets
from opti.core.secretbox import Keyring, generate_key

pytestmark = pytest.mark.db

NOW = datetime(2026, 10, 12, tzinfo=UTC)
FALLBACK = {"smtp_password": "OPTI_SECRET_ALERTING_SMTP_PASSWORD"}


def _keyring() -> Keyring:
    k = Keyring.from_env({"OPTI_ENCRYPTION_KEY": generate_key()})
    assert k is not None
    return k


async def test_write_resolve_and_states(session: AsyncSession) -> None:
    k = _keyring()
    env = {"OPTI_SECRET_ALERTING_SMTP_PASSWORD": "from-env"}
    names = {"smtp_password", "channel:a:webhook_url"}
    r = await secrets.resolve(session, "alerting", names, k, fallback=FALLBACK, env=env)
    assert r.values == {"smtp_password": "from-env", "channel:a:webhook_url": None}
    before = await secrets.stamp(session, "alerting")
    await secrets.write(session, "alerting", {"channel:a:webhook_url": "https://hook.example/abcd1234wxyz"},
                        keyring=k, user="ops", now=NOW)  # fmt: skip
    assert await secrets.stamp(session, "alerting") != before
    r = await secrets.resolve(session, "alerting", names, k, fallback=FALLBACK, env=env)
    assert r.values["channel:a:webhook_url"] == "https://hook.example/abcd1234wxyz"
    states = {
        s.name: s
        for s in await secrets.states(session, "alerting", names, fallback=FALLBACK, env=env)
    }
    assert (
        states["channel:a:webhook_url"].source == "db"
        and states["channel:a:webhook_url"].hint == "wxyz"
    )
    assert states["smtp_password"].source == "env" and states["smtp_password"].hint is None


async def test_clear_masks_environment(session: AsyncSession) -> None:
    k = _keyring()
    env = {"OPTI_SECRET_ALERTING_SMTP_PASSWORD": "from-env"}
    await secrets.write(
        session, "alerting", {"smtp_password": None}, keyring=None, user="ops", now=NOW
    )
    r = await secrets.resolve(session, "alerting", {"smtp_password"}, k, fallback=FALLBACK, env=env)
    assert r.values == {"smtp_password": None}
    [state] = await secrets.states(
        session, "alerting", {"smtp_password"}, fallback=FALLBACK, env=env
    )
    assert (state.set, state.source) == (False, "none")


async def test_write_needs_keyring(session: AsyncSession) -> None:
    with pytest.raises(secrets.SecretWriteError):
        await secrets.write(
            session, "alerting", {"smtp_password": "x"}, keyring=None, user="ops", now=NOW
        )


async def test_decrypt_failure_is_a_problem_not_an_error(session: AsyncSession) -> None:
    await secrets.write(
        session,
        "alerting",
        {"smtp_password": "secret-value"},
        keyring=_keyring(),
        user="ops",
        now=NOW,
    )
    r = await secrets.resolve(
        session, "alerting", {"smtp_password"}, _keyring(), fallback={}, env={}
    )
    assert r.values == {"smtp_password": None} and "smtp_password" in r.problems
    assert "secret-value" not in r.problems["smtp_password"]


async def test_prune_and_rekey(session: AsyncSession) -> None:
    old_key = generate_key()
    old = Keyring.from_env({"OPTI_ENCRYPTION_KEY": old_key})
    assert old is not None
    await secrets.write(session, "alerting", {"channel:a:webhook_url": "https://a", "channel:b:webhook_url": "https://b",
                                              "smtp_password": "p"}, keyring=old, user="ops", now=NOW)  # fmt: skip
    assert await secrets.prune(session, "alerting", {"channel:a:webhook_url", "smtp_password"}) == [
        "channel:b:webhook_url"
    ]
    new = Keyring.from_env(
        {"OPTI_ENCRYPTION_KEY": generate_key(), "OPTI_ENCRYPTION_KEY_PREVIOUS": old_key}
    )
    assert new is not None
    assert await secrets.rekey(session, new) == 2
    r = await secrets.resolve(
        session, "alerting", {"channel:a:webhook_url"}, new, fallback={}, env={}
    )
    assert r.values == {"channel:a:webhook_url": "https://a"}


async def test_stored_only_resolution_skips_names_without_rows(session: AsyncSession) -> None:
    k = _keyring()
    env = {"OPTI_SECRET_OTX_API_KEY": "from-env"}
    await secrets.write(session, "connectors", {"otx:api_key": "stored", "urlscan:api_key": None},
                        keyring=k, user="ops", now=NOW)  # fmt: skip
    names = {"otx:api_key", "urlscan:api_key", "hibp:api_key"}
    r = await secrets.resolve(
        session, "connectors", names, k, fallback={}, env=env, stored_only=True
    )
    assert r.values == {"otx:api_key": "stored", "urlscan:api_key": None}


async def test_rekey_covers_connector_credentials_and_preserves_clears(
    session: AsyncSession,
) -> None:
    old_key, new_key = generate_key(), generate_key()
    old = Keyring.from_env({"OPTI_ENCRYPTION_KEY": old_key})
    rotating = Keyring.from_env(
        {"OPTI_ENCRYPTION_KEY": new_key, "OPTI_ENCRYPTION_KEY_PREVIOUS": old_key}
    )
    new = Keyring.from_env({"OPTI_ENCRYPTION_KEY": new_key})
    assert old is not None and rotating is not None and new is not None
    await secrets.write(
        session,
        "connectors",
        {"otx:api_key": "web-key", "urlscan:api_key": None},
        keyring=old,
        user="ops",
        now=NOW,
    )
    assert await secrets.rekey(session, rotating) == 1
    result = await secrets.resolve(
        session,
        "connectors",
        {"otx:api_key", "urlscan:api_key"},
        new,
        fallback={},
        stored_only=True,
    )
    assert result.values == {"otx:api_key": "web-key", "urlscan:api_key": None}
    assert result.problems == {}
