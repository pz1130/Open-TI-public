"""DMARC 聚合报告解析（设计文档 4.5、4.12）。报告来自外部发件方：禁止 DTD/实体，限制解压后大小。"""

from __future__ import annotations

import io
import ipaddress
import zipfile
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

MAX_XML_BYTES = 20 * 1024 * 1024


class DmarcError(ValueError):
    pass


@dataclass(frozen=True)
class DmarcRecord:
    source_ip: str
    count: int
    header_from: str
    disposition: str
    dkim: str
    spf: str


@dataclass(frozen=True)
class DmarcReport:
    org_name: str
    report_id: str
    date_begin: datetime
    date_end: datetime
    domain: str
    records: tuple[DmarcRecord, ...]


def _limited(data: bytes) -> bytes:
    if len(data) > MAX_XML_BYTES:
        raise DmarcError(f"报告解压后超过上限 {MAX_XML_BYTES} 字节")
    return data


def unpack(name: str, data: bytes) -> bytes:
    lowered = name.lower()
    if lowered.endswith(".xml"):
        return _limited(data)
    if lowered.endswith(".gz"):
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            output = _limited(d.decompress(data, MAX_XML_BYTES + 1))
            if not d.eof or d.unused_data:
                raise DmarcError("gzip 不完整或包含多个报告")
            return output
        except zlib.error as e:
            raise DmarcError("gzip 格式错误") from e
    if lowered.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                members = [i for i in z.infolist() if not i.is_dir()]
                if len(members) != 1:
                    raise DmarcError("zip 中应只有一个报告文件")
                if members[0].file_size > MAX_XML_BYTES:
                    raise DmarcError(f"报告解压后超过上限 {MAX_XML_BYTES} 字节")
                with z.open(members[0]) as f:
                    return _limited(f.read(MAX_XML_BYTES + 1))
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as e:
            raise DmarcError("zip 格式错误") from e
    raise DmarcError(f"不支持的附件：{name}")


def _text(el: Element | None, path: str, default: str = "") -> str:
    node = el.find(path) if el is not None else None
    return (node.text or "").strip() if node is not None and node.text else default


def _ts(value: str) -> datetime:
    return datetime.fromtimestamp(int(value), UTC)


def parse_report(xml: bytes) -> DmarcReport:
    try:
        root = fromstring(
            _limited(xml), forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except (DefusedXmlException, ParseError) as e:
        raise DmarcError(f"报告 XML 不合法或含被禁止的结构：{type(e).__name__}") from e
    if root.tag.startswith("{urn:ietf:params:xml:ns:dmarc"):
        for node in root.iter():
            node.tag = node.tag.rsplit("}", 1)[-1]
    if root.tag != "feedback":
        raise DmarcError("报告根节点必须为 feedback")
    try:
        meta = root.find("report_metadata")
        records = tuple(
            DmarcRecord(
                source_ip=str(ipaddress.ip_address(_text(rec, "row/source_ip"))),
                count=int(_text(rec, "row/count", "0")),
                header_from=_text(rec, "identifiers/header_from").lower(),
                disposition=_text(rec, "row/policy_evaluated/disposition"),
                dkim=_text(rec, "row/policy_evaluated/dkim"),
                spf=_text(rec, "row/policy_evaluated/spf"),
            )
            for rec in root.findall("record")
        )
        report = DmarcReport(
            org_name=_text(meta, "org_name"),
            report_id=_text(meta, "report_id"),
            date_begin=_ts(_text(meta, "date_range/begin", "0")),
            date_end=_ts(_text(meta, "date_range/end", "0")),
            domain=_text(root, "policy_published/domain").lower(),
            records=records,
        )
        if (
            not report.domain
            or not report.org_name
            or not report.report_id
            or report.date_end < report.date_begin
        ):
            raise ValueError("缺少报告标识、域名或日期范围不合法")
        if len(report.org_name) > 200 or len(report.report_id) > 500 or len(report.domain) > 253:
            raise ValueError("报告元数据过长")
        for record in records:
            if len(record.header_from) > 253 or record.disposition not in (
                "none",
                "quarantine",
                "reject",
            ):
                raise ValueError("发件域或处置结果不合法")
            ipaddress.ip_address(record.source_ip)
            if (
                record.count <= 0
                or record.dkim not in ("pass", "fail")
                or record.spf not in ("pass", "fail")
            ):
                raise ValueError("数量或对齐结果不合法")
        return report
    except (ValueError, OverflowError, OSError) as e:
        raise DmarcError("报告字段不合法") from e
