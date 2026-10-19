from opti.core.extract import MAX_ARTICLE_CHARS, extract_article

PARAGRAPH = (
    "The Sample Brand approved a new loan to support renewable energy projects "
    "in the region on Monday. Officials said the financing will help build solar and "
    "wind capacity over the next five years. "
)
HTML = (
    '<html lang="en-GB"><head><title>Bank approves loan | Example News</title></head>'
    "<body><nav>Home | World | Business | Subscribe now</nav><article>"
    "<h1>Bank approves loan</h1>"
    + "".join(f"<p>{PARAGRAPH}</p>" for _ in range(6))
    + "</article><footer>Copyright Example News. Cookie settings.</footer></body></html>"
)


def test_extract_article() -> None:
    article = extract_article(HTML, "https://news.example/a")
    assert article is not None and article.url == "https://news.example/a"
    assert "renewable energy" in article.text
    assert "Cookie settings" not in article.text and "Subscribe now" not in article.text
    assert "Bank approves loan" in article.title and article.language == "en"


def test_extract_empty_and_capped() -> None:
    assert (
        extract_article("<html><body><nav>menu</nav></body></html>", "https://x.example/") is None
    )
    article = extract_article(HTML.replace(PARAGRAPH, PARAGRAPH * 400), "https://news.example/a")
    assert article is not None and len(article.text) <= MAX_ARTICLE_CHARS
