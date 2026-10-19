import pytest

from opti.sandbox.guard import request_allowed


def _resolver(mapping: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    async def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    return resolve


RESOLVE = _resolver({
    "sbr-loans.com": ["93.184.216.34"],
    "intranet.example": ["10.0.0.5"],
    "mixed.example": ["93.184.216.34", "127.0.0.1"],
    "metadata.example": ["169.254.169.254"],
})  # fmt: skip


@pytest.mark.parametrize(
    ("method", "url", "allowed"),
    [
        ("GET", "https://sbr-loans.com/login", True),
        ("HEAD", "http://sbr-loans.com/", True),
        ("POST", "https://sbr-loans.com/login", False),  # 不提交表单（设计文档 2.2）
        ("PUT", "https://sbr-loans.com/x", False),
        ("GET", "https://intranet.example/", False),
        ("GET", "https://mixed.example/", False),
        ("GET", "http://metadata.example/latest/meta-data/", False),
        ("GET", "https://nxdomain.example/", False),
        ("GET", "ftp://sbr-loans.com/x", False),
        ("GET", "file:///etc/passwd", False),
        ("GET", "data:image/png;base64,AAAA", True),
        ("GET", "https://sbr-loans.com:99999/", False),
    ],
)
async def test_guard_blocks_private_and_non_get(method: str, url: str, allowed: bool) -> None:
    assert await request_allowed(method, url, resolve=RESOLVE) is allowed


async def test_allow_private_is_test_only_switch() -> None:
    assert await request_allowed(
        "GET", "https://intranet.example/", resolve=RESOLVE, allow_private=True
    )
    assert not await request_allowed(
        "POST", "https://intranet.example/", resolve=RESOLVE, allow_private=True
    )
