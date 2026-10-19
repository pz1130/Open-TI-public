import json
from datetime import UTC, datetime

from opti.sdk.models import RawItem, raw_item_from_dict, raw_item_to_dict


def test_roundtrip_through_json() -> None:
    item = RawItem(
        "certstream",
        "p1",
        datetime(2026, 10, 2, 8, 0, tzinfo=UTC),
        None,
        {"matches": [{"domain": "sbr-loans.com"}], "cert": {"all_domains": ("a", "b")}},
        project_ids=("sample-brand-protection",),
    )
    back = raw_item_from_dict(json.loads(json.dumps(raw_item_to_dict(item))))
    assert back.item_id == item.item_id
    assert back.fetched_at == item.fetched_at
    assert back.project_ids == item.project_ids
    assert back.payload["cert"]["all_domains"] == ["a", "b"]
