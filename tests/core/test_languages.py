from opti.core.languages import detect_language


def test_detects_languages_locally_and_abstains_on_short_text() -> None:
    assert (
        detect_language(
            "Sample Brand approved a new loan for renewable energy infrastructure in South Africa."
        )
        == "en"
    )
    assert (
        detect_language("样本品牌宣布在成员国扩大绿色基础设施融资，支持可持续发展项目。") == "zh"
    )
    assert (
        detect_language(
            "El banco anunció nuevos préstamos para proyectos de energía renovable en la región."
        )
        == "es"
    )
    assert detect_language("SBR loan") is None
    assert (
        detect_language(
            "https://example.com/this-is-a-long-url-with-english-words-in-it-and-brand-name"
        )
        is None
    )
