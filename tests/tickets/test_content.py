import json
from datetime import UTC, datetime
from typing import Any

from opti.alerting.views import AlertView
from opti.tickets.content import comment_content, issue_content, title, to_adf, to_text

T = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
VIEW = AlertView(
    alert_id=7, project_id="p", severity="high", category="phishing_site", domain="acme-loans.com",
    score=80, reasons=("brand_label",), first_seen=T, created_at=T, link="https://ti.example/alerts/7",
)  # fmt: skip
EXPOSURE = {
    "exposure": {
        "source": "hibp", "title": "Example breach", "domain": "acme.org", "breach_date": "2026-09-01",
        "data_classes": ["Email addresses", "Passwords"], "accounts": ["a@acme.org", "b@acme.org"],
        "advice": "请强制修改口令",
    }
}  # fmt: skip


def _links(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for mark in node.get("marks", []):
            if mark.get("type") == "link":
                found.append(mark["attrs"]["href"])
        for child in node.get("content", []):
            found += _links(child)
    return found


def test_title_defangs_and_truncates() -> None:
    assert title(VIEW, 250) == "[Open-TI][高] 钓鱼网站：acme-loans[.]com"
    long = AlertView(**{**VIEW.__dict__, "domain": "a" * 300 + ".com"})
    cut = title(long, 160)
    assert len(cut) == 160 and cut.endswith("…")


def test_issue_text_and_adf() -> None:
    content = issue_content(VIEW, None, include_accounts=False)
    text = to_text(content)
    assert "告警编号：7" in text and "域名 / URL：acme-loans[.]com" in text
    assert text.endswith("在平台中查看：https://ti.example/alerts/7")
    adf = to_adf(content)
    assert adf["type"] == "doc" and adf["version"] == 1
    assert _links(adf) == ["https://ti.example/alerts/7"]  # 只有平台链接可点击
    assert "acme-loans.com" not in json.dumps(adf, ensure_ascii=False)


def test_exposure_accounts_follow_switch() -> None:
    hidden = to_text(issue_content(VIEW, EXPOSURE, include_accounts=False))
    assert "a@acme.org" not in hidden and "受影响账户：2 个，请在平台查看" in hidden
    assert "数据类型：Email addresses、Passwords" in hidden
    shown = issue_content(VIEW, EXPOSURE, include_accounts=True)
    assert shown.accounts == ("a@acme.org", "b@acme.org")
    assert "- a@acme.org" in to_text(shown)
    assert "a@acme.org" in json.dumps(to_adf(shown))


def test_comment_for_follow_up_batch() -> None:
    content = comment_content(VIEW, EXPOSURE, include_accounts=False)
    text = to_text(content)
    assert text.startswith("Open-TI 告警 7：新增受影响账户 2 个")
    assert "a@acme.org" not in text and "来源：hibp" in text


def test_secrets_in_reasons_are_masked() -> None:
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    view = AlertView(**{**VIEW.__dict__, "reasons": (f"token {token}",)})
    assert token not in to_text(issue_content(view, None, include_accounts=False))


def test_long_account_lists_are_capped() -> None:
    # Jira 描述上限 32767 字符，ServiceNow description 默认 4000：只列前 100 个，其余在平台查看
    accounts = [f"user{i:04d}@acme.org" for i in range(250)]
    extra = {"exposure": {**EXPOSURE["exposure"], "accounts": accounts}}
    for content in (
        issue_content(VIEW, extra, include_accounts=True),
        comment_content(VIEW, extra, include_accounts=True),
    ):
        assert content.accounts == tuple(accounts[:100])
        text = to_text(content)
        assert "受影响账户：共 250 个，下面列出前 100 个，其余 150 个请在平台查看" in text
        assert "user0100@acme.org" not in text
    short = to_text(issue_content(VIEW, EXPOSURE, include_accounts=True))
    assert "下面列出前" not in short
