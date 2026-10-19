from opti.sdk.context import MemoryCursorStore, ProjectCursorStore


def test_search_progress_is_independent_and_survives_switching_back() -> None:
    shared = MemoryCursorStore()
    shared.set("source", "since:same-query", "legacy")
    first = ProjectCursorStore(shared, "first")
    second = ProjectCursorStore(shared, "second")
    assert first.get("source", "since:same-query") is None
    first.set("source", "since:same-query", "first-page")
    assert second.get("source", "since:same-query") is None
    second.set("source", "since:same-query", "second-page")
    assert ProjectCursorStore(shared, "first").get("source", "since:same-query") == "first-page"
    assert ProjectCursorStore(shared, "second").get("source", "since:same-query") == "second-page"
    assert first.get("another-source", "since:same-query") is None
