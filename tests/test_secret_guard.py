"""Regression: discovered secrets are never sent out, used for auth, or stored/logged raw."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from opti.core.secret_guard import (
    MaskSecretsFilter,
    SecretEgressBlocked,
    assert_no_secret,
    discovered,
    mask_deep,
    mask_text,
)
from opti.core.secrets import redact_findings
from opti.core.stix import build_bundle
from opti.sdk.http import HttpError, RateLimitedHttpClient

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
OPAQUE = "Zq9-opaque-Secret-Value-77"  # no recognisable shape: only the registry knows it


@pytest.fixture(autouse=True)
def _clean_registry():
    discovered.clear()
    yield
    discovered.clear()


def test_mask_keeps_prefix_only():
    out = mask_text(f"key={AWS} tok {GH}")
    assert AWS not in out and GH not in out
    assert "AKIA…[REDACTED:" in out and "ghp_…[REDACTED:" in out
    # hashes / ids are untouched
    h = "a" * 64
    assert mask_text(h) == h


def test_mask_deep_payload():
    doc = mask_deep({"a": [AWS, {"b": f"x {GH}"}], "n": 3})
    assert AWS not in json.dumps(doc) and GH not in json.dumps(doc)
    assert doc["n"] == 3


def test_redact_findings_registers_digest_not_value():
    out = redact_findings([{"Secret": OPAQUE, "File": "cfg.env", "RuleID": "generic"}], "r")
    assert OPAQUE not in json.dumps(out)
    assert discovered.hit(f"Authorization: Bearer {OPAQUE}")
    assert OPAQUE not in repr(discovered.__dict__)


def test_guard_blocks_patterns_in_url_and_body():
    with pytest.raises(SecretEgressBlocked):
        assert_no_secret("t", url=f"https://x.test/?k={AWS}")
    with pytest.raises(SecretEgressBlocked):
        assert_no_secret("t", body={"text": GH})
    # configured API tokens in headers are allowed by shape...
    assert_no_secret("t", url="https://api.github.com", headers={"Authorization": f"token {GH}"})


def test_guard_blocks_discovered_value_even_in_headers():
    redact_findings([{"Secret": OPAQUE, "File": "a"}], "r")
    with pytest.raises(SecretEgressBlocked):
        assert_no_secret("t", url="https://x.test", headers={"X-Key": OPAQUE})
    with pytest.raises(SecretEgressBlocked):
        assert_no_secret("t", url=f"https://x.test/login?pw={OPAQUE}")


async def test_http_client_refuses_and_never_sends():
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={})

    redact_findings([{"Secret": OPAQUE, "File": "a"}], "r")
    async with RateLimitedHttpClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(HttpError) as ei:
            await http.post_json("https://hooks.test/x", {"alert": f"leaked {AWS}"})
        assert AWS not in str(ei.value)
        with pytest.raises(HttpError):
            await http.get("https://probe.test/", headers={"Authorization": f"Bearer {OPAQUE}"})
        with pytest.raises(HttpError):
            await http.post_bytes("https://siem.test/", OPAQUE.encode(), headers={})
        await http.get("https://ok.test/")
    assert [str(r.url) for r in sent] == ["https://ok.test/"]


def test_log_filter_masks():
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "found %s", (AWS,), None)
    MaskSecretsFilter().filter(rec)
    assert AWS not in rec.getMessage()


def test_outbound_scrub_masks_credentials_for_llm():
    from opti.core.adjudication import OutboundFilter
    from opti.core.config import parse_project_rules
    from tests.core.test_adjudication import RULES

    f = OutboundFilter(parse_project_rules(RULES))
    out = f.scrub(
        f"password = hunter2-secret\n{AWS}\n-----BEGIN RSA PRIVATE KEY-----\nMIIx\n-----END RSA PRIVATE KEY-----"
    )
    assert AWS not in out and "hunter2-secret" not in out and "MIIx" not in out


def test_stix_bundle_is_masked():
    assert build_bundle([], project="p", organization="o", base_url="https://x") is not None
    assert AWS not in json.dumps(mask_deep({"description": AWS}))


def test_same_prefix_secrets_mask_differently():
    a, b = "AKIA" + "A" * 16, "AKIA" + "B" * 16
    assert mask_text(a) != mask_text(b)
    assert mask_text(a).startswith("AKIA…[REDACTED:")


def test_collector_and_processor_masks_are_identical():
    from datetime import UTC, datetime

    from opti.core.secret_guard import mask_item
    from opti.core.secrets import redact_text
    from opti.sdk.models import RawItem

    collector = redact_text(f"k={AWS}")  # collector-side snippet redaction
    item = RawItem("pastebin", "1", datetime.now(UTC), None, {"t": f"k={AWS}"})
    assert mask_item(item).payload["t"] == collector == f"k={mask_text(AWS)}"


def test_mask_is_keyed_hmac_not_bare_sha256(monkeypatch):
    import hashlib

    from opti.core.secrets import fingerprint

    bare = hashlib.sha256(AWS.encode()).hexdigest()
    out = redact_findings([{"Secret": AWS, "File": "f"}], "r")
    assert bare not in json.dumps(out) and bare[:8] not in mask_text(AWS)
    assert out[0]["fingerprint"] == fingerprint(AWS) and "sha256" not in out[0]
    first = mask_text(AWS)
    monkeypatch.setenv("OPTI_SECRET_MASK_KEY", "another-key-" + "1" * 32)
    assert mask_text(AWS) != first  # depends on the key


def test_missing_key_fails_closed(monkeypatch):
    from opti.core.secrets import MaskKeyMissing, require_mask_key

    monkeypatch.setenv("OPTI_SECRET_MASK_KEY", "short")
    with pytest.raises(MaskKeyMissing):
        require_mask_key()
    with pytest.raises(MaskKeyMissing):
        mask_text(AWS)
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "found %s", (AWS,), None)
    MaskSecretsFilter().filter(rec)  # logging degrades to untagged mask, never raw
    assert AWS not in rec.getMessage()


def test_legacy_bare_sha256_from_old_collector_is_dropped():
    from datetime import UTC, datetime

    from opti.core.codehits import safe_scan

    legacy = {"scanned": True, "secrets": [{"sha256": "f" * 64, "file": "a", "line": 1}]}
    assert safe_scan(legacy, "a/b", datetime.now(UTC))["secrets"] == []
