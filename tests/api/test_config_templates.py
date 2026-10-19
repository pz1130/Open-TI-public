from tests.api.conftest import ApiWorld


async def test_builtin_templates_and_preview(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    await make_user("viewer", ("viewer",))
    client = await login("viewer")
    response = await client.get("/api/v1/config/takedown_templates")
    assert response.status_code == 200
    body = response.json()
    assert body["builtin"]["zh-CN"]["cdn"].startswith("Subject:")
    preview = await client.post(
        "/api/v1/config/takedown_templates/preview",
        json={"language": "zh-CN", "kind": "cdn", "text": "Subject: 投诉 $domain\n致 $target_name"},
    )
    assert preview.status_code == 200
    result = preview.json()
    assert result["errors"] == []
    assert result["subject"].startswith("投诉 ") and "[.]" in result["subject"]
    invalid = await client.post(
        "/api/v1/config/takedown_templates/preview",
        json={"language": "zh-CN", "kind": "cdn", "text": "Subject: x\n$nope"},
    )
    assert invalid.json()["errors"] == ["未知的占位符：$nope"]


async def test_saved_template_is_in_live_snapshot(api: ApiWorld, make_user, login) -> None:  # type: ignore[no-untyped-def]
    await make_user("ops", ("platform_admin",))
    client = await login("ops")
    data = (await client.get("/api/v1/config/takedown_templates")).json()["data"]
    data["zh-CN"]["cdn"] = "Subject: 已改 $domain\n$org_name"
    response = await client.put(
        "/api/v1/config/takedown_templates", json={"data": data, "base_version": 0}
    )
    assert response.status_code == 200
    assert api.deps.config.snapshot.takedown_templates.text("zh-CN", "cdn").startswith(
        "Subject: 已改"
    )
