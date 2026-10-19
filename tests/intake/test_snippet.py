from opti.intake.snippet import canary_snippets


def test_snippets_embed_official_domains_and_token() -> None:
    js, css = canary_snippets(
        "https://www.example.org/ti-intake/", "t" * 32, ["example.org", "example.int"]
    )
    assert '["example.org","example.int"]' in js
    assert "https://www.example.org/ti-intake/b/" + "t" * 32 + ".gif?v=js&h=" in js
    assert js.startswith("<script>") and "location.hostname" in js
    assert (
        css
        == 'body{background-image:url("https://www.example.org/ti-intake/b/'
        + "t" * 32
        + '.gif?v=css")}'
    )


def test_base_url_is_validated() -> None:
    import pytest

    with pytest.raises(ValueError):
        canary_snippets('https://x.org/"><script>', "t" * 32, ["x.org"])
    with pytest.raises(ValueError):
        canary_snippets("ftp://x.org/", "t" * 32, ["x.org"])


def test_unicode_official_domain_uses_browser_hostname_and_safe_json() -> None:
    js, _ = canary_snippets(
        "https://example.org/ti-intake", "t" * 32, ["银行.example", "x</script>.example"]
    )
    assert "xn--" in js and js.count("</script>") == 1
