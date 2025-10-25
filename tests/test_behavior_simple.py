# csp-check/test/test_behavior.py
from csp_check.csp_check import URLResult, Policy, SourceItem, LatexRenderer


def _mk_result(
    with_default_src: bool = True,
    warnings: dict | None = None,
) -> URLResult:
    # Minimal URLResult to exercise behavior mapping (no network / no file output)
    policies = []
    if with_default_src:
        policies.append(Policy(name="default-src", items=[SourceItem(raw="'self'", normalized="'self'")]))

    # Include some directive so object structure isn't empty
    policies.append(Policy(name="script-src", items=[SourceItem(raw="'self'", normalized="'self'")]))

    return URLResult(
        url="https://example.com",
        requested_url="https://example.com",
        csp_raw="default-src 'self'; script-src 'self';" if with_default_src else "script-src 'self';",
        policies=policies,
        deprecated_used=[],
        warnings=warnings or {},
        error=None,
    )


def test_problems_list_mapping_and_order():
    """
    Verify that LatexRenderer._problems_list maps URLResult.warnings and
    policy presence to the expected, ordered problem list without touching output code.
    """
    # Construct warnings that should trigger all problem categories when default-src is missing
    warnings = {
        "unsafe_inline": True,  # -> "unsafe"
        "unsafe_eval": True,  # -> "unsafe" (already covered)
        "wildcard_sources": True,  # -> "all-origins"
        "data_or_blob": True,  # -> "data"
        "missing_report_to": True,  # -> "no-report"
        "missing_https_and_upgrade": True,  # -> "no-https"
    }
    res = _mk_result(with_default_src=False, warnings=warnings)
    lr = LatexRenderer(lang="en")

    probs = lr._problems_list(res)
    expected_order = ["missing-directive", "unsafe", "no-https", "all-origins", "data", "no-report"]
    assert probs == expected_order


def test_normalize_lang_accepts_synonyms():
    """
    Ensure language normalization accepts both short and long forms.
    """
    lr_en = LatexRenderer(lang="english")
    lr_de = LatexRenderer(lang="german")
    assert lr_en.lang == "en"
    assert lr_de.lang == "de"
