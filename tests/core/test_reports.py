from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from opti.alerting.config import AlertingConfig
from opti.core.reports import MAX_LINES, empty_content, render_html, render_text, report_view, title

START, END = datetime(2026, 10, 2, 1, tzinfo=UTC), datetime(2026, 10, 3, 1, tzinfo=UTC)
BASE = "https://ti.example"


def _content(**change: Any) -> dict[str, Any]:
    c = empty_content("daily", start=START, end=END, language="zh-CN", timezone="Asia/Shanghai")
    c["totals"] = {"findings": 3, "alerts": 2, "critical": 0, "high": 1, "medium": 1, "low": 1}
    c["by_category"] = [{"category": "typosquat_domain", "findings": 2, "alerts": 1}]
    c["alerts"] = [
        {
            "alert_id": 7,
            "severity": "medium",
            "category": "typosquat_domain",
            "subject": "sbr-loans.com",
            "score": 50,
        }
    ]
    c["news"] = [
        {
            "finding_id": 9,
            "alert_id": None,
            "category": "brand_mention",
            "title": "<script>alert(1)</script> SBR",
            "url": "https://news.example/a",
            "source": "Example News",
            "summary": "批准贷款",
            "score": 25,
        }
    ]
    c["vulnerabilities"] = [{"finding_id": 11, "alert_id": 8, "cve": "CVE-2026-12345", "name": "EdgeGate VPN Bypass",
                             "software": ["Example Networks EdgeGate VPN"], "severity": "medium", "score": 55}]  # fmt: skip
    c.update(change)
    return c


def test_title_and_timezone() -> None:
    assert title(_content()) == "威胁情报日报 2026-10-03"
    text = render_text(_content(), BASE, f"{BASE}/reports/1")
    assert "2026-10-02 09:00 – 2026-10-03 09:00" in text  # 按 Asia/Shanghai 显示
    en = empty_content("weekly", start=START, end=END, language="en-US", timezone="UTC")
    assert title(en) == "Threat intelligence weekly report 2026-10-03"


def test_render_escapes_and_defangs() -> None:
    html = render_html(_content(), BASE, f"{BASE}/reports/1")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "sbr-loans[.]com" in html and "sbr-loans.com" not in html and "news[.]example" in html
    hrefs = [part.split("'")[0] for part in html.split("href='")[1:]]
    assert hrefs == [f"{BASE}/alerts/7", f"{BASE}/alerts/8", f"{BASE}/reports/1"]  # 只链接回平台
    text = render_text(_content(), BASE, f"{BASE}/reports/1")
    assert "sbr-loans[.]com" in text and "https://news.example" not in text and "批准贷款" in text
    assert "CVE-2026-12345" in text and f"{BASE}/alerts/7" in text


def test_report_defangs_domains_inside_news_text() -> None:
    c = _content()
    c["news"][0]["title"] = "Read evil.example now"
    c["news"][0]["summary"] = "Visit https://evil.example/path"
    view = report_view(3, c, BASE)
    assert "evil.example" not in view.text and "evil.example" not in view.html
    assert "evil.example" not in "".join(view.lines)
    assert "evil[.]example" in view.text


def test_report_view_lines_capped() -> None:
    many = [{"alert_id": i, "severity": "medium", "category": "typosquat_domain", "subject": f"sbr-{i}.top", "score": 50}
            for i in range(100)]  # fmt: skip
    view = report_view(3, _content(alerts=many, news=[], vulnerabilities=[]), BASE)
    assert view.link == f"{BASE}/reports/3" and len(view.lines) == MAX_LINES + 1
    assert view.lines[-1] == f"另有 {100 - MAX_LINES} 条，请在平台中查看"
    assert ("新告警", "2") in view.facts and view.title == "威胁情报日报 2026-10-03"


def test_weekly_sections_and_empty() -> None:
    w = empty_content("weekly", start=START, end=END, language="zh-CN", timezone="UTC")
    w["low"] = {
        "count": 4,
        "top": [
            {"finding_id": 1, "category": "typosquat_domain", "subject": "sbr-old.top", "score": 25}
        ],
    }
    w["triage"] = {"false_positive": 2, "true_positive": 5}
    w["takedowns"] = {"opened": 1, "resolved": 3}
    text = render_text(w, BASE, f"{BASE}/reports/2")
    assert "sbr-old[.]top" in text and "误报：2" in text and "新建：1" in text and "完成：3" in text
    assert "无" in render_text(
        empty_content("daily", start=START, end=END), BASE, f"{BASE}/reports/4"
    )


def test_report_settings() -> None:
    cfg = AlertingConfig()
    assert (cfg.report_language, cfg.report_timezone) == ("zh-CN", "UTC")
    with pytest.raises(ValidationError):
        AlertingConfig(report_timezone="Mars/Olympus")
    with pytest.raises(ValidationError):
        AlertingConfig.model_validate({"report_language": "fr-FR"})


SEPT, OCT = datetime(2026, 8, 31, 16, tzinfo=UTC), datetime(2026, 9, 30, 16, tzinfo=UTC)


def _monthly(language: str = "zh-CN") -> dict[str, Any]:
    c = empty_content("monthly", start=SEPT, end=OCT, language=language, timezone="Asia/Shanghai")
    c["totals"] = {"findings": 8, "alerts": 4, "critical": 1, "high": 1, "medium": 2, "low": 4}
    c["previous"] = {"findings": 9, "alerts": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}
    c["by_category"] = [{"category": "typosquat_domain", "alerts": 2, "previous": 0}]
    c["alerts"] = [
        {"alert_id": 7, "severity": "high", "category": "typosquat_domain", "subject": "sbr-old.top", "score": 70,
         "status": "closed", "verdict": "true_positive", "takedown": "submitted"},
        {"alert_id": 8, "severity": "critical", "category": "phishing_site", "subject": "<b>sbr-pay.top</b>",
         "score": 90, "status": "open", "verdict": None, "takedown": None},
    ]  # fmt: skip
    c["news"] = [{"finding_id": 9, "alert_id": None, "category": "negative_press", "title": "SBR fined",
                  "url": "https://news.example/a", "source": "Example News", "summary": "", "score": 30}]  # fmt: skip
    c["counts"] = {"news": 12, "vulnerabilities": 0}
    c["trend"] = [
        {"month": "2026-08", "critical": 0, "high": 1, "medium": 0},
        {"month": "2026-09", "critical": 1, "high": 1, "medium": 2},
    ]
    return c


def test_monthly_title_names_the_month() -> None:
    assert title(_monthly()) == "威胁情报月报 2026-09"  # 按报告时区，不是周期结束日
    assert title(_monthly("en-US")) == "Threat intelligence monthly report 2026-09"


def test_monthly_text_compares_with_previous_month() -> None:
    text = render_text(_monthly(), BASE, f"{BASE}/reports/5")
    assert "新告警：4（上月 1，+3）" in text and "新发现：8（上月 9，-1）" in text
    assert "仿冒域名：2 / 0" in text
    assert "[高] 仿冒域名：sbr-old[.]top（70 分） — 已关闭（真实威胁）· 下架：已提交" in text
    assert "[严重] 钓鱼网站：<b>sbr-pay[.]top</b>（90 分） — 待处理" in text
    assert "负面舆情与冒名诈骗提及（共 12 条）" in text and "SBR fined" in text
    assert "2026-09：严重 1 · 高 1 · 中 2" in text
    en = render_text(_monthly("en-US"), BASE, f"{BASE}/reports/5")
    assert (
        "New alerts: 4 (prev. 1, +3)" in en and "Closed (True positive) · Takedown: Submitted" in en
    )


def test_monthly_html_trend_escaping_and_print_styles() -> None:
    html = render_html(_monthly(), BASE, f"{BASE}/reports/5")
    assert "&lt;b&gt;sbr-pay[.]top&lt;/b&gt;" in html and "<b>" not in html
    assert "<th>2026-09</th>" in html and "width:100%" in html  # 趋势条按最大月份等比
    assert "@page" in html and "break-inside:avoid" in html
    hrefs = [part.split("'")[0] for part in html.split("href='")[1:]]
    assert hrefs == [f"{BASE}/alerts/7", f"{BASE}/alerts/8", f"{BASE}/reports/5"]


def test_monthly_push_card() -> None:
    view = report_view(5, _monthly(), BASE)
    assert view.title == "威胁情报月报 2026-09" and ("新告警", "4（上月 1，+3）") in view.facts
    assert view.lines[0].endswith("已关闭（真实威胁）· 下架：已提交")


def test_impersonation_account_has_report_names() -> None:
    from opti.core.reports import CATEGORY_NAMES

    assert CATEGORY_NAMES["zh-CN"]["impersonation_account"] == "冒充账号"
    assert CATEGORY_NAMES["en-US"]["impersonation_account"] == "Impersonation account"
