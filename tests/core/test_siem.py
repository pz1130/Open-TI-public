from dataclasses import replace
from datetime import UTC, datetime

from opti.core.siem import SiemEvent, cef, hec_payload, octet_framed, syslog_frame

T = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
EVENT = SiemEvent(
    alert_id=7, project_id="demo", severity="high", category="phishing_site", score=80,
    reasons=("brand_label", "login_form"), entity_type="url", entity_value="https://sbr-loans.com/login?a=1",
    title="https://sbr-loans.com/login?a=1", created_at=T, link="https://ti.example/alerts/7",
)  # fmt: skip


def test_cef_fields() -> None:
    line = cef(EVENT, version="0.1.0")
    head = line.split("|")[:7]
    assert head == [
        "CEF:0",
        "Open-TI",
        "Open-TI",
        "0.1.0",
        "phishing_site",
        "Open-TI phishing_site alert",
        "8",
    ]
    assert f"rt={int(T.timestamp() * 1000)}" in line and "externalId=7" in line
    assert "dhost=sbr-loans.com" in line and "request=https://sbr-loans.com/login?a\\=1" in line
    assert "cs1Label=reasons cs1=brand_label,login_form" in line and "cn1Label=score cn1=80" in line
    assert "cs2=https://ti.example/alerts/7" in line


def test_cef_escaping() -> None:
    nasty = replace(EVENT, category="x|y", entity_type="document", entity_value="cluster:1",
                    title="a|b=c\\d\nfake=1 cs2=evil")  # fmt: skip
    line = cef(nasty, version="1|2")
    assert (
        "\n" not in line
        and line.split("|")[3] == "1\\"
        and "CEF:0|Open-TI|Open-TI|1\\|2|x\\|y|" in line
    )
    assert "msg=a|b\\=c\\\\d\\nfake\\=1 cs2\\=evil" in line
    assert line.count(" cs2=") == 1 and "dhost=" not in line  # 文本类没有观测值


def test_observables() -> None:
    assert EVENT.observables() == {
        "url": "https://sbr-loans.com/login?a=1",
        "domain": "sbr-loans.com",
    }
    ip6 = replace(EVENT, entity_type="ip", entity_value="2001:db8::1")
    assert "c6a2=2001:db8::1" in cef(ip6, version="0") and "c6a2Label=ip" in cef(ip6, version="0")
    assert "dst=203.0.113.5" in cef(
        replace(EVENT, entity_type="ip", entity_value="203.0.113.5"), version="0"
    )
    cve = replace(
        EVENT,
        category="vulnerability",
        entity_type="cve",
        entity_value="CVE-2026-1",
        title="CVE-2026-1 X",
    )
    assert cve.observables() == {"cve": "CVE-2026-1"}
    own = replace(
        EVENT,
        category="unapproved_certificate",
        entity_type="domain",
        entity_value="portal.sbr.int",
    )
    assert own.observables() == {} and "dhost=" not in cef(
        own, version="0"
    )  # 本机构自己的域名不能作为可阻断的观测值


def test_json_and_hec() -> None:
    doc = EVENT.to_json()
    assert (
        doc["event"] == "alert.opened"
        and doc["id"] == "opti-alert-7"
        and doc["created_at"] == "2026-10-03T08:00:00+00:00"
    )
    assert doc["observables"]["domain"] == "sbr-loans.com" and doc["reasons"] == [
        "brand_label",
        "login_form",
    ]
    hec = hec_payload(EVENT)
    assert (
        hec["sourcetype"] == "opti:alert" and hec["time"] == T.timestamp() and hec["event"] == doc
    )


def test_syslog_frame() -> None:
    frame = syslog_frame(
        "hello 世界", severity="high", hostname="ti host\n", app_name="opti", now=T
    )
    assert frame == "<131>1 2026-10-03T08:00:00.000Z tihost opti - opti-alert - hello 世界".encode()
    assert octet_framed(b"abc") == b"3 abc"
    assert syslog_frame("x", severity="info", hostname="", app_name="opti", now=T).startswith(
        b"<134>1 "
    )
