from datetime import UTC, datetime
from pathlib import Path

import pytest

from opti.organization import Organization
from opti.takedown.render import (
    KINDS,
    LANGUAGES,
    EvidenceLine,
    TemplateError,
    build_context,
    defang_url,
    render,
)
from opti.takedown.targets import Target

TEMPLATES = Path(__file__).resolve().parents[2] / "config" / "takedown" / "templates"
ORG = Organization(
    name="Example Organization", short_name="Example", website="https://www.example.org",
    security_contact="mailto:security@example.org", legal_statement="本机构授权对冒用行为进行处置。",
    legal_statement_en="We are authorized.", takedown_sender="abuse-response@example.org",
    signature="Example Security Team",
)  # fmt: skip
TARGET = Target("registrar", "registrar:cheap", "Cheap Registrar LLC", "abuse@registrar.example", None, "rdap_registrar")  # fmt: skip
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
SHOT = EvidenceLine("screenshot", datetime(2026, 10, 2, 8, 1, tzinfo=UTC), "a" * 64, "https://login.sbr-loans.com/x.html")  # fmt: skip


def _ctx(language: str, target: Target = TARGET) -> dict[str, str]:
    return build_context(
        ORG, target, language=language, host="login.sbr-loans.com",
        url="https://login.sbr-loans.com/x.html", category="phishing_site",
        first_seen=datetime(2026, 10, 1, tzinfo=UTC), evidence=[SHOT], ips=["104.16.1.1"], now=NOW,
    )  # fmt: skip


def test_defang_url() -> None:
    assert defang_url("HTTPS://a.b/c.html") == "hxxps://a[.]b/c[.]html"


def test_render_zh_and_en() -> None:
    zh = render(TEMPLATES, "zh-CN", "registrar", _ctx("zh-CN"))
    assert "login[.]sbr-loans[.]com" in zh.subject and "Example Organization" in zh.subject
    assert "hxxps://login[.]sbr-loans[.]com/x[.]html" in zh.body and "a" * 64 in zh.body
    assert "本机构授权" in zh.body and "Example Security Team" in zh.body and "钓鱼网站" in zh.body
    assert "abuse-response@example.org" in zh.body
    en = render(TEMPLATES, "en-US", "registrar", _ctx("en-US"))
    assert en.subject.startswith("Abuse report") and "We are authorized." in en.body
    assert "phishing website" in en.body and "本机构" not in en.body


def test_every_repository_template_renders_completely() -> None:
    for language in LANGUAGES:
        for kind in KINDS:
            m = render(TEMPLATES, language, kind, _ctx(language))
            assert "$" not in m.subject + m.body, (language, kind)  # 占位符拼写错误会原样留下 $
            assert "\n" not in m.subject and 0 < len(m.subject) <= 200
            assert "Example Organization" in m.body
            source = (TEMPLATES / language / f"{kind}.txt").read_text(encoding="utf-8").casefold()
            assert "sbr" not in source  # 模板不写死任何机构


def test_no_evidence_and_bad_inputs(tmp_path: Path) -> None:
    ctx = build_context(
        ORG, TARGET, language="en-US", host="sbr-loans.com", url=None, category="typosquat_domain",
        first_seen=NOW, evidence=[], ips=[], now=NOW,
    )  # fmt: skip
    assert ctx["evidence"].startswith("(No screenshot") and ctx["url"] == "sbr-loans[.]com"
    assert ctx["ips"] == "-" and ctx["org_contact"] == "abuse-response@example.org"
    with pytest.raises(TemplateError):
        render(TEMPLATES, "fr-FR", "registrar", ctx)
    with pytest.raises(TemplateError):
        render(tmp_path, "en-US", "registrar", ctx)  # 模板文件不存在
    (tmp_path / "en-US").mkdir()
    (tmp_path / "en-US" / "registrar.txt").write_text("no subject line\n", encoding="utf-8")
    with pytest.raises(TemplateError):
        render(tmp_path, "en-US", "registrar", ctx)


def test_single_line_fields_cannot_inject_headers(tmp_path: Path) -> None:
    (tmp_path / "en-US").mkdir()
    (tmp_path / "en-US" / "report.txt").write_text(
        "Subject: $target_name\n\nbody\n", encoding="utf-8"
    )
    evil = Target(
        "report", "report:x", "A\r\nBcc: x@y.example", None, "https://r.example", "reporting"
    )
    m = render(tmp_path, "en-US", "report", _ctx("en-US", evil))
    assert m.subject == "A Bcc: x@y.example" and m.body == "body\n"


def test_manual_categories_have_takedown_text() -> None:
    from opti.takedown.render import CATEGORY_TEXT

    for language in ("zh-CN", "en-US"):
        assert {"impersonation_account", "fraud_scam"} <= set(CATEGORY_TEXT[language])


def test_platform_template_includes_description() -> None:
    target = Target(
        "platform",
        "platform:linkedin",
        "LinkedIn",
        None,
        "https://www.linkedin.com/help/x",
        "platform",
    )
    for language in ("zh-CN", "en-US"):
        ctx = build_context(
            Organization(name="Example Org"), target, language=language, host="www.linkedin.com",
            url="https://www.linkedin.com/in/fake-ceo/", category="impersonation_account",
            first_seen=datetime(2026, 10, 7, tzinfo=UTC), evidence=[], ips=[],
            now=datetime(2026, 10, 7, tzinfo=UTC), detail="冒充行长发布招聘",
        )  # fmt: skip
        m = render(TEMPLATES, language, "platform", ctx)
        assert "冒充行长发布招聘" in m.body
        assert "linkedin[.]com" in m.body and "$" not in m.subject + m.body


def test_render_from_validated_template_model() -> None:
    from opti.takedown.templates import TakedownTemplates, templates_from_dir

    data = templates_from_dir(TEMPLATES).data()
    data["zh-CN"]["registrar"] = "Subject: 新主题 $domain\n正文 $org_name\n"
    material = render(TakedownTemplates.model_validate(data), "zh-CN", "registrar", _ctx("zh-CN"))
    assert material.subject == "新主题 login[.]sbr-loans[.]com"
    assert material.body == "正文 Example Organization\n"
