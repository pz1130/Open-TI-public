from opti.sdk.context import MemoryCursorStore


def test_dump_returns_only_that_connector() -> None:
    s = MemoryCursorStore()
    s.set("crtsh", "q:sbr", "42")
    s.set("crtsh", "q:orbit", "7")
    s.set("nrd", "whoisds:last_date", "2026-10-01")
    assert s.dump("crtsh") == {"q:sbr": "42", "q:orbit": "7"}
    assert s.dump("none") == {}
