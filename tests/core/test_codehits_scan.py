from datetime import UTC, datetime
from typing import Any

from opti.core.codehits import safe_scan, sanitize_scan_result
from opti.core.secrets import fingerprint

NOW = datetime(2026, 10, 17, 8, 0, tzinfo=UTC)
FAKE_AWS = "AKIA" + "QYLPMN5HTWX2BVFC"
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _secret(**overrides: Any) -> dict[str, Any]:
    return {"rule": "aws-access-token", "description": "AWS", "file": "config/app.env", "line": 2,
            "commit": "c" * 40, "date": "2026-09-20T00:00:00Z", "prefix": "AKIA",
            "fingerprint": "f" * 64, "length": 20, **overrides}  # fmt: skip


def _scan(*secrets: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"supported": True, "scanned": True, "commit": "a" * 40, "depth": 100,
            "total": len(secrets), "secrets": list(secrets), **extra}  # fmt: skip


def test_context_is_allowlisted_and_masked_again() -> None:
    context = ["# settings", f"AWS={FAKE_AWS}", f"GH={FAKE_GH}", "ab " * 200, 7, "a", "b", "c", "d"]
    [secret] = safe_scan(_scan(_secret(context=context)), "acme/tools", NOW)["secrets"]
    assert len(secret["context"]) == 7
    assert secret["context"][0] == "# settings"
    assert secret["context"][1] == f"AWS=AKIA…[REDACTED:{fingerprint(FAKE_AWS)[:8]}]"
    assert FAKE_GH[4:] not in secret["context"][2]
    assert len(secret["context"][3]) == 200
    assert secret["context"][4:] == ["a", "b", "c"]


def test_missing_or_bad_context_is_empty() -> None:
    for value in (None, "AWS=x", {"line": 1}):
        [secret] = safe_scan(_scan(_secret(context=value)), "acme/tools", NOW)["secrets"]
        assert secret["context"] == []
    [legacy] = safe_scan(_scan(_secret()), "acme/tools", NOW)["secrets"]
    assert legacy["context"] == []


def test_repo_meta_is_cleaned_and_masked() -> None:
    meta = {"description": f"Deploy {FAKE_AWS}", "homepage": "https://acme.example", "owner": "acme",
            "owner_type": "Robot", "fork": "yes", "topics": ["deploy", 3], "created_at": "yesterday",
            "pushed_at": "2026-09-20T00:00:00Z", "extra": "dropped"}  # fmt: skip
    out = safe_scan(_scan(repo_meta=meta), "acme/tools", NOW)["repo_meta"]
    assert out == {
        "description": f"Deploy AKIA…[REDACTED:{fingerprint(FAKE_AWS)[:8]}]",
        "homepage": "https://acme.example",
        "owner": "acme",
        "owner_type": "",
        "fork": False,
        "topics": ["deploy"],
        "created_at": "",
        "pushed_at": "2026-09-20T00:00:00Z",
    }
    assert safe_scan(_scan(), "acme/tools", NOW)["repo_meta"] == {}


def test_sanitize_keeps_context_and_meta() -> None:
    data = _scan(_secret(context=["AWS=AKIA…[REDACTED:12345678]"]), repo_meta={"owner": "acme"})
    out = sanitize_scan_result(data, "github.com/acme/tools", NOW)
    assert out["secrets"][0]["context"] == ["AWS=AKIA…[REDACTED:12345678]"]
    assert out["repo_meta"]["owner"] == "acme"
