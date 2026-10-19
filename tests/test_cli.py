import io
import json
from pathlib import Path

import pytest

from opti.cli import main


def test_match_domain(sbr_rules_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--rules", str(sbr_rules_path), "match-domain", "sbr-loans.com", "crossbrace.com"])
    assert rc == 0
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert lines[0]["status"] == "match"
    assert lines[0]["score"]["severity"] == "medium"
    assert lines[0]["score"]["breakdown"]["base"] == 20
    assert {r["reason"] for r in lines[0]["reasons"]} >= {"brand_label", "fraud_affix"}
    assert lines[1] == {"input": "crossbrace.com", "status": "no_match"}


def test_match_domain_official_has_no_score(
    sbr_rules_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--rules", str(sbr_rules_path), "match-domain", "mail.sbr.int"])
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "official" and "score" not in out


def test_match_text(
    sbr_rules_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("SBR 样本国家 低息贷款"))
    assert main(["--rules", str(sbr_rules_path), "match-text"]) == 0
    hits = json.loads(capsys.readouterr().out)
    assert {h["term"] for h in hits} == {"SBR", "低息贷款"}


def test_bad_rules_path_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--rules", str(tmp_path / "missing.yaml"), "match-domain", "x.com"])
    assert rc == 2
    assert "找不到" in capsys.readouterr().err


def test_invalid_rules_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "k.yaml"
    p.write_text("project: t\nsets: {}\ndomains: {official: [a.b], brand_tokens: [x]}\n")
    assert main(["--rules", str(p), "match-domain", "x.com"]) == 2
    assert "authorization_ref" in capsys.readouterr().err
