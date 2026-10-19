from datetime import UTC, datetime
from typing import Any

from opti.db.models import Alert, Feedback
from opti.pipeline.triage import apply_status, apply_verdict

NOW = datetime(2026, 10, 8, 8, 0, tzinfo=UTC)


class _Session:
    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def _alert(status: str = "open") -> Alert:
    return Alert(id=1, project_id="p", severity="high", status=status, created_at=NOW)


def test_apply_status_sets_closed_at_only_when_closed() -> None:
    alert = _alert()
    apply_status(alert, "closed", NOW)
    assert (alert.status, alert.closed_at, alert.updated_at) == ("closed", NOW, NOW)
    apply_status(alert, "open", NOW)
    assert (alert.status, alert.closed_at) == ("open", None)


def test_apply_verdict_closes_or_acknowledges() -> None:
    session = _Session()
    alert = _alert()
    apply_verdict(session, alert, 3, user_id=9, verdict="false_positive", reason="r", now=NOW)  # type: ignore[arg-type]
    assert (alert.status, alert.triage_verdict, alert.closed_at) == (
        "closed",
        "false_positive",
        NOW,
    )
    [fb] = session.added
    assert isinstance(fb, Feedback)
    assert (fb.alert_id, fb.finding_id, fb.user_id, fb.verdict, fb.reason) == (
        1,
        3,
        9,
        "false_positive",
        "r",
    )
    alert = _alert()
    apply_verdict(session, alert, 3, user_id=9, verdict="true_positive", reason="", now=NOW)  # type: ignore[arg-type]
    assert (alert.status, alert.closed_at) == ("acknowledged", None)
    superseded = _alert("superseded")
    apply_verdict(session, superseded, 3, user_id=9, verdict="duplicate", reason="", now=NOW)  # type: ignore[arg-type]
    assert (superseded.status, superseded.triage_verdict, superseded.updated_at) == (
        "superseded",
        "duplicate",
        NOW,
    )
