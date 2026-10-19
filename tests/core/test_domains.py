import pytest

from opti.core.domains import normalize_domain, parse_domain, skeleton


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("*.SBR.INT.", "sbr.int"),
        ("Mail.Sbr.Int", "mail.sbr.int"),
        ("xn--br-loans-jhh.com", "ѕbr-loans.com"),
        ("xn--zz.sbr-loans.com", "xn--zz.sbr-loans.com"),  # 无法解码的标签保留原样
        ("", None),
        ("localhost", None),
        ("1.2.3.4", None),
        ("a b.com", None),
        ("user@sbr-loans.com", None),
        ("x" * 64 + ".com", None),
        (("a" * 60 + ".") * 5 + "com", None),  # 超过 253 个字符
    ],
)
def test_normalize_domain(raw: str, expected: str | None) -> None:
    assert normalize_domain(raw) == expected


def test_parse_subdomain_disguise() -> None:
    p = parse_domain("sbr.int.secure-login.xyz")
    assert p is not None
    assert p.registered == "secure-login.xyz"
    assert p.label == "secure-login"
    assert p.subdomain_labels == ("sbr", "int")


def test_parse_official_subdomain() -> None:
    p = parse_domain("mail.sbr.int")
    assert p is not None and p.registered == "sbr.int"


def test_private_suffix_is_registrable() -> None:
    p = parse_domain("sbr-loans.github.io")
    assert p is not None
    assert p.registered == "sbr-loans.github.io"
    assert p.label == "sbr-loans"
    assert p.subdomain_labels == ()


def test_multi_part_suffix() -> None:
    p = parse_domain("orbitbank-invest.com.cn")
    assert p is not None and p.suffix == "com.cn" and p.label == "orbitbank-invest"


def test_unknown_tld_falls_back_to_last_label() -> None:
    p = parse_domain("www.sbr-loans.notarealtld")
    assert p is not None
    assert p.registered == "sbr-loans.notarealtld"
    assert p.subdomain_labels == ("www",)


def test_parse_invalid() -> None:
    assert parse_domain("localhost") is None


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("sbr", "sbr"),
        ("ѕbr", "sbr"),  # 西里尔 ѕ
        ("ЅBR", "sbr"),  # 西里尔 Ѕ
        ("śbr", "sbr"),  # 变音符号
        ("sbr-lοans", "sbr-loans"),  # 希腊 ο
    ],
)
def test_skeleton(label: str, expected: str) -> None:
    assert skeleton(label) == expected
