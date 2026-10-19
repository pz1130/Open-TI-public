import json
import re

import pytest

from opti.core.secrets import (
    fingerprint,
    is_critical_rule,
    is_sensitive_path,
    mask,
    redact_findings,
    redact_text,
)

FAKE_AWS = "AKIA" + "QYLPMN5HTWX2BVFC"
FAKE_GH = "ghp_" + "x7Lq2Vb9Nc4Rt8Wm1Zp6Ks3Jd5Hf0Ga2Yu4E"


def test_mask_and_redact_text() -> None:
    assert re.fullmatch(r"AKIA…\[REDACTED:[0-9a-f]{8}\]", mask(FAKE_AWS))
    assert re.fullmatch(r"…\[REDACTED:[0-9a-f]{8}\]", mask("abc"))
    for text, kept, gone in (
        (f"aws_access_key_id = {FAKE_AWS}", "AKIA…[REDACTED:", FAKE_AWS[4:]),
        (f"token: {FAKE_GH}", "ghp_…[REDACTED:", FAKE_GH[8:]),
        ('DB_PASSWORD="aaaa-bbbb-cccc"', "DB_PASSWORD=", "aaaa-bbbb-cccc"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
            "PRIVATE KEY",
            "MIIEow",
        ),
        ("see https://portal.example.org/login", "https://portal.example.org/login", "[REDACTED]"),
    ):
        out = redact_text(text)
        assert kept in out and gone not in out


def test_rules_and_paths() -> None:
    assert is_critical_rule("aws-access-token") and is_critical_rule("github-pat")
    assert not is_critical_rule("generic-api-key")
    for path in (
        ".env",
        "config/.env.production",
        "deploy/id_rsa",
        "app/settings.py",
        "infra/main.tfvars",
    ):
        assert is_sensitive_path(path), path
    for path in ("README.md", "docs/index.html", "src/main.go"):
        assert not is_sensitive_path(path), path


def test_redact_findings_keeps_no_secret_or_author() -> None:
    raw = [
        {"RuleID": "aws-access-token", "Description": "AWS", "File": "config/app.env", "StartLine": 3,
         "Commit": "a" * 40, "Date": "2026-09-01T00:00:00Z", "Secret": FAKE_AWS, "Match": f"KEY={FAKE_AWS}",
         "Author": "Jane Dev", "Email": "jane@example.org", "Message": "add keys"},
        {"RuleID": "aws-access-token", "File": "config/app.env", "StartLine": 9, "Secret": FAKE_AWS},
        {"RuleID": "generic-api-key", "File": "a b/c#d.py", "StartLine": 1, "Commit": "c" * 40,
         "Secret": "aaaabbbbccccdddd"},
        "garbage",
        {"RuleID": "x", "File": "f", "Secret": ""},
    ]  # fmt: skip
    out = redact_findings(raw, "acme/tools")
    blob = json.dumps(out)
    for leaked in (FAKE_AWS[4:], "aaaabbbbccccdddd", "Jane", "jane", "add keys", "KEY="):
        assert leaked not in blob
    assert out[0] == {
        "rule": "aws-access-token", "description": "AWS", "file": "config/app.env", "line": 3,
        "commit": "a" * 40, "date": "2026-09-01T00:00:00Z", "prefix": "AKIA",
        "fingerprint": fingerprint(FAKE_AWS), "length": 20,
        "url": f"https://github.com/acme/tools/blob/{'a' * 40}/config/app.env#L3",
    }  # fmt: skip
    assert len(out) == 2 and out[1]["url"].endswith("/a%20b/c%23d.py#L1")
    assert len(redact_findings([raw[0]] * 300, "acme/tools")) == 1


@pytest.mark.parametrize("bad_line", ["oops", object()])
def test_redact_findings_tolerates_bad_line(bad_line: object) -> None:
    assert (
        redact_findings([{"Secret": "aaaabbbb", "StartLine": bad_line}], "acme/tools")[0]["line"]
        == 0
    )
