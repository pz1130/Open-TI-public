from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from opti.core import policy
from opti.core.scoring import Severity, severity_for
from opti.core.secretbox import (
    ENV_CURRENT,
    Keyring,
    generate_key,
    initialize_master_key,
    master_key_path,
)
from opti.core.webpages import page_kind
from opti.pipeline.watchlist import WatchState, next_interval
from opti.sdk.schedules import valid_cron


def test_business_policy_changes_classification_and_recheck(monkeypatch) -> None:
    configured = policy.OperationsConfig.model_validate(
        {
            "risk": {"high_score": 70},
            "watchlist": {"urgent_hours": 2},
            "pages": {
                "parking_hosts": ["market.example"],
                "sale_phrases": ["THIS DOMAIN IS LISTED"],
            },
        }
    )
    monkeypatch.setattr(policy, "_current", configured)
    assert severity_for(65) == Severity.MEDIUM
    now = datetime.now(UTC)
    assert next_interval(WatchState.LIVE, created_at=now, now=now) == timedelta(hours=2)
    assert (
        page_kind({"reachable": True, "status": 200, "final_url": "https://market.example"})
        == "parking"
    )


@pytest.mark.parametrize(
    "value", ["*/0 * * * *", "60 * * * *", "* * * *", "* * * * 9", "10-1 * * * *"]
)
def test_invalid_schedule_rejected(value: str) -> None:
    assert not valid_cron(value)
    with pytest.raises(ValidationError):
        policy.OperationsConfig(schedules={"recheck_watchlist": value})


def test_master_key_persists_without_exposing_or_overwriting(tmp_path: Path) -> None:
    raw = generate_key()
    ring = initialize_master_key(tmp_path, raw)
    loaded = Keyring.from_env({}, state_dir=tmp_path)
    assert loaded is not None
    assert loaded.decrypt(ring.encrypt("token", aad="test"), aad="test") == "token"
    assert master_key_path(tmp_path).stat().st_mode & 0o777 == 0o600
    assert master_key_path(tmp_path).parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        initialize_master_key(tmp_path, generate_key())
    assert master_key_path(tmp_path).read_text().strip() == raw
    environment = Keyring.from_env({ENV_CURRENT: generate_key()}, state_dir=tmp_path)
    assert environment is not None and not environment.is_current(ring.encrypt("x", aad="test"))
