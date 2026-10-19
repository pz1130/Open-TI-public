import gzip
import io
import zipfile

import pytest

from opti.core.dmarc import MAX_XML_BYTES, DmarcError, parse_report, unpack

REPORT = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>123</report_id>
    <date_range><begin>1790000000</begin><end>1790086400</end></date_range></report_metadata>
  <policy_published><domain>sbr.int</domain><p>reject</p></policy_published>
  <record><row><source_ip>45.33.32.156</source_ip><count>140</count>
    <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>sbr.int</header_from></identifiers></record>
  <record><row><source_ip>40.107.1.1</source_ip><count>900</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>sbr.int</header_from></identifiers></record>
</feedback>"""


def test_parse_report() -> None:
    r = parse_report(REPORT)
    assert (r.org_name, r.report_id, r.domain) == ("google.com", "123", "sbr.int")
    assert r.date_begin.isoformat() == "2026-09-21T14:13:20+00:00"
    assert [(x.source_ip, x.count, x.dkim, x.spf) for x in r.records] == [
        ("45.33.32.156", 140, "fail", "fail"), ("40.107.1.1", 900, "pass", "pass"),
    ]  # fmt: skip


def test_unpack_formats() -> None:
    assert unpack("r.xml", REPORT) == REPORT
    assert unpack("r.xml.gz", gzip.compress(REPORT)) == REPORT
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("google.com!sbr.int!1!2.xml", REPORT)
    assert unpack("r.zip", buf.getvalue()) == REPORT
    with pytest.raises(DmarcError):
        unpack("r.pdf", b"%PDF")


def test_rejects_xxe_and_bombs() -> None:
    xxe = b'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback>&x;</feedback>'
    with pytest.raises(DmarcError):
        parse_report(xxe)
    laughs = b'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><feedback>&b;</feedback>'
    with pytest.raises(DmarcError):
        parse_report(laughs)
    bomb = gzip.compress(b"\0" * (MAX_XML_BYTES + 1))
    with pytest.raises(DmarcError, match="上限"):
        unpack("r.xml.gz", bomb)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.xml", b"\0" * (MAX_XML_BYTES + 1))
    with pytest.raises(DmarcError, match="上限"):
        unpack("r.zip", buf.getvalue())
    with pytest.raises(DmarcError):
        parse_report(b"<feedback><record><row><count>x</count></row></record></feedback>")


@pytest.mark.parametrize(
    "data", [gzip.compress(REPORT)[:-5], gzip.compress(REPORT) + gzip.compress(REPORT)]
)
def test_rejects_incomplete_or_concatenated_gzip(data: bytes) -> None:
    with pytest.raises(DmarcError):
        unpack("r.gz", data)


def test_direct_xml_limit_and_namespaced_report() -> None:
    with pytest.raises(DmarcError, match="上限"):
        parse_report(b"x" * (MAX_XML_BYTES + 1))
    xml = REPORT.replace(b"<feedback>", b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">')
    assert parse_report(xml).records == parse_report(REPORT).records


@pytest.mark.parametrize(
    "xml",
    [
        REPORT.replace(b"<count>140</count>", b"<count>-1</count>"),
        REPORT.replace(b"45.33.32.156", b"invalid-ip"),
        REPORT.replace(b"1790000000", b"999999999999999999999"),
    ],
)
def test_rejects_invalid_record_fields(xml: bytes) -> None:
    with pytest.raises(DmarcError):
        parse_report(xml)
