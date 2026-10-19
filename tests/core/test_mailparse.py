import hashlib
from email.message import EmailMessage

from opti.core.mailparse import extract_urls, parse_eml, parse_graph_message


def test_extract_urls_from_text_and_html() -> None:
    text = (
        "请点击 https://login-portal.top/verify?id=1 或 hxxps://evil[.]top/a 。退订：mailto:x@y.z"
    )
    assert extract_urls(text) == ["https://login-portal.top/verify?id=1", "https://evil.top/a"]
    html = '<a href="https://evil.top/x">点这里</a><img src="cid:abc"><img src="https://cdn.top/i.png">'
    assert extract_urls(html, html=True) == ["https://evil.top/x", "https://cdn.top/i.png"]


def test_safe_links_are_unwrapped() -> None:
    wrapped = (
        "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Flogin-portal.top%2Fverify"
        "&data=05%7C01&reserved=0"
    )
    assert extract_urls(f"<a href='{wrapped}'>x</a>", html=True) == [
        "https://login-portal.top/verify"
    ]


def test_limit_and_dedupe() -> None:
    text = " ".join(f"https://a{i}.top/" for i in range(150)) + " https://a1.top/"
    urls = extract_urls(text, limit=100)
    assert len(urls) == 100 and len(set(urls)) == 100


def _eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "Help Desk <it-support@helpdesk-login.top>"
    msg["Reply-To"] = "reply@other-domain.top"
    msg["Return-Path"] = "<bounce@mailer.top>"
    msg["Subject"] = "密码即将过期" + "！" * 300
    msg["Message-ID"] = "<abc@helpdesk-login.top>"
    msg["Authentication-Results"] = "mx.example.org; spf=fail smtp.mailfrom=mailer.top; dkim=none"
    msg.set_content("请访问 https://helpdesk-login.top/reset 立即重置。")
    msg.add_alternative(
        '<p><a href="https://helpdesk-login.top/reset2">重置</a></p>', subtype="html"
    )
    msg.add_attachment(
        b"MZ\x90\x00 evil", maintype="application", subtype="octet-stream", filename="invoice.exe"
    )
    return msg.as_bytes()


def test_parse_eml() -> None:
    r = parse_eml(_eml())
    assert r.sender_domain == "helpdesk-login.top" and r.reply_to_domain == "other-domain.top"
    assert r.return_path_domain == "mailer.top" and r.message_id == "<abc@helpdesk-login.top>"
    assert r.urls == ("https://helpdesk-login.top/reset", "https://helpdesk-login.top/reset2")
    assert len(r.subject) == 200 and r.auth_results is not None and "spf=fail" in r.auth_results


def test_attachments_hashed_not_opened() -> None:
    r = parse_eml(_eml())
    [a] = r.attachments
    assert a.name == "invoice.exe" and a.size == len(b"MZ\x90\x00 evil")
    assert a.sha256 == hashlib.sha256(b"MZ\x90\x00 evil").hexdigest()


def test_parse_graph_message() -> None:
    msg = {
        "subject": "Your mailbox is full",
        "internetMessageId": "<x@evil.top>",
        "from": {"emailAddress": {"address": "admin@mailbox-quota.top"}},
        "replyTo": [{"emailAddress": {"address": "r@reply.top"}}],
        "internetMessageHeaders": [
            {"name": "Return-Path", "value": "<b@bounce.top>"},
            {"name": "Authentication-Results", "value": "spf=softfail"},
        ],
        "body": {
            "contentType": "html",
            "content": '<a href="https://mailbox-quota.top/login">upgrade</a>',
        },
    }
    r = parse_graph_message(msg)
    assert (r.sender_domain, r.reply_to_domain, r.return_path_domain) == (
        "mailbox-quota.top",
        "reply.top",
        "bounce.top",
    )
    assert r.urls == ("https://mailbox-quota.top/login",) and r.auth_results == "spf=softfail"
    assert r.attachments == ()


def test_garbage_does_not_crash() -> None:
    r = parse_eml(b"\x00\xff not an email")
    assert r.urls == () and r.sender_domain is None
    assert parse_graph_message({}).subject == ""


def test_common_defanged_links() -> None:
    assert extract_urls("Visit hxxps[:]//evil(.)top/login and hxxp://other[.]top/x") == [
        "https://evil.top/login",
        "http://other.top/x",
    ]
    assert extract_urls('<a href="hxxps[:]//evil[.]top/login">link</a>', html=True) == [
        "https://evil.top/login",
    ]
