import email
import email.policy
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

import pytest

from opti.db.models import Alert, Entity, Evidence, Finding, Takedown
from opti.organization import Organization
from opti.storage.objects import MemoryObjectStore
from opti.takedown.bundle import BundleError, build_eml, evidence_bundle
from opti.takedown.stats import StatRow, compute

NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 100
HTML = b"<html><form><input type=password></form></html>"


async def _evidence(store: MemoryObjectStore) -> list[Evidence]:
    out = []
    for i, (kind, data, ctype) in enumerate(
        [("screenshot", PNG, "image/png"), ("html", HTML, "text/html")], start=1
    ):
        await store.put(f"ev/{i}", data, ctype)
        out.append(
            Evidence(
                id=i, finding_id=1, alert_id=1, kind=kind, object_key=f"ev/{i}",
                sha256=hashlib.sha256(data).hexdigest(), size=len(data), content_type=ctype,
                captured_at=NOW, node_id="hk1", method="opti-sandbox/test",
                source_url="https://login.sbr-loans.com/x.html",
            )
        )  # fmt: skip
    return out


def _alert() -> tuple[Alert, Finding, Entity]:
    alert = Alert(id=1, project_id="p", severity="high", status="open", created_at=NOW,
                  routing={"category": "phishing_site", "score": 80})  # fmt: skip
    finding = Finding(id=1, project_id="p", entity_id=1, category="phishing_site", score=80, severity="high",
                      status="new", score_breakdown={}, match={}, sources=["urlscan"], first_seen=NOW, last_seen=NOW)  # fmt: skip
    entity = Entity(id=1, type="url", value="https://login.sbr-loans.com/x.html", first_seen=NOW, last_seen=NOW,
                    enrichment={"rdap": {"data": {"registrar": "Cheap Registrar LLC"}}})  # fmt: skip
    return alert, finding, entity


async def test_evidence_bundle_contents_and_integrity() -> None:
    store = MemoryObjectStore()
    evidence = await _evidence(store)
    alert, finding, entity = _alert()
    data = await evidence_bundle(
        store, alert=alert, finding=finding, entity=entity, evidence=evidence, now=NOW
    )
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = set(zf.namelist())
    assert {
        "README.txt",
        "manifest.json",
        "SHA256SUMS",
        "evidence/1-screenshot.png",
        "evidence/2-html.txt",
    } == names
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["entity"]["defanged"] == "hxxps://login[.]sbr-loans[.]com/x[.]html"
    assert manifest["registration"] == {"registrar": "Cheap Registrar LLC"}
    assert manifest["evidence"][0]["source_url"] == "hxxps://login[.]sbr-loans[.]com/x[.]html"
    assert manifest["evidence"][0]["uploaded_by"] is None  # 沙箱截图没有上传人
    for line in zf.read("SHA256SUMS").decode().splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256(zf.read(name)).hexdigest() == digest
    evidence[0].sha256 = "0" * 64  # 对象存储中的文件与记录不一致
    with pytest.raises(BundleError) as e:
        await evidence_bundle(
            store, alert=alert, finding=finding, entity=entity, evidence=evidence, now=NOW
        )
    assert e.value.status == 409


async def test_eml_is_unsent_draft_with_screenshots_only() -> None:
    store = MemoryObjectStore()
    evidence = await _evidence(store)
    org = Organization(name="Example Organization", takedown_sender="abuse-response@example.org")
    td = Takedown(id=3, subject="Abuse report: sbr-loans[.]com", body="Dear team,\n",
                  target={"kind": "registrar", "id": "registrar:x", "name": "X", "email": "abuse@registrar.example"})  # fmt: skip
    msg = email.message_from_bytes(
        await build_eml(store, org, td, evidence), policy=email.policy.default
    )
    assert msg["To"] == "abuse@registrar.example" and msg["From"] == "abuse-response@example.org"
    assert msg["X-Unsent"] == "1" and msg["Subject"] == "Abuse report: sbr-loans[.]com"
    attachments = [p.get_filename() for p in msg.iter_attachments()]
    assert attachments == ["evidence-1.png"]  # HTML 快照不随邮件发出
    td.target = {**td.target, "email": "x@y.example\nBcc: z@w.example"}
    with pytest.raises(BundleError) as e:
        await build_eml(store, org, td, evidence)
    assert e.value.status == 409
    plain = await build_eml(
        None,
        org,
        Takedown(id=4, subject="s", body="b\n", target={"email": "a@b.example"}),
        evidence,
    )
    assert (
        list(email.message_from_bytes(plain, policy=email.policy.default).iter_attachments()) == []
    )  # 未配置对象存储：不附截图


def test_stats() -> None:
    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    h = lambda n: t0.replace(hour=n)  # noqa: E731
    rows = [
        StatRow("removed", "Cheap Registrar LLC", "registrar", h(2), h(4), h(10), t0),
        StatRow("rejected", "Cheap Registrar LLC", "registrar", h(2), None, h(8), t0),
        StatRow("submitted", "Host Co", "hosting", h(3), None, None, t0),
        StatRow("draft", "Host Co", "hosting", None, None, None, t0),
    ]
    out = compute(rows)
    assert out["by_state"] == {"removed": 1, "rejected": 1, "submitted": 1, "draft": 1}
    assert out["mttr_hours"] == 10.0
    assert out["targets"] == [
        {
            "name": "Host Co",
            "kind": "hosting",
            "total": 2,
            "removed": 0,
            "rejected": 0,
            "median_response_hours": None,
        },
        {
            "name": "Cheap Registrar LLC",
            "kind": "registrar",
            "total": 2,
            "removed": 1,
            "rejected": 1,
            "median_response_hours": 4.0,
        },
    ]
