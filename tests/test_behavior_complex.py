# csp-check/test/test_behavior_more.py
from csp_check.csp_check import (
    URLResult,
    Policy,
    SourceItem,
    LatexRenderer,
    pretty_csp,
    highlight_csp_problems,
    is_wildcard_token,
)


def _mk_result(
    csp_raw: str,
    warnings: dict | None = None,
    policies: list[Policy] | None = None,
) -> URLResult:
    return URLResult(
        url="https://example.com",
        requested_url="https://example.com",
        csp_raw=csp_raw,
        policies=policies or [],
        deprecated_used=[],
        warnings=warnings or {},
        error=None,
    )


def test_pretty_csp_formatting():
    """pretty_csp should break the header into lines and end with a semicolon."""
    raw = "default-src 'self'; script-src 'self' 'unsafe-inline';  img-src https://cdn.example;"
    formatted = pretty_csp(raw)
    # Each directive moved to its own line with leading two spaces and joined by ';\n'
    lines = formatted.splitlines()
    # Last char should be a semicolon
    assert formatted.endswith(";")
    # Number of lines equals number of non-empty directives
    assert len(lines) == 3


def test_highlight_marks_http_when_missing_https_and_upgrade():
    """When missing_https_and_upgrade is True, only http:// sources are highlighted."""
    raw = "default-src https://good.example http://bad.example; img-src https://ok.example;"
    res = _mk_result(
        csp_raw=raw,
        warnings={"missing_https_and_upgrade": True},
        policies=[Policy(name="default-src"), Policy(name="img-src")],
    )
    formatted = pretty_csp(raw)
    highlighted = highlight_csp_problems(formatted, res)
    print(highlighted)

    assert "§R[http://bad.example]R§" in highlighted
    assert "https://good.example" in highlighted
    assert "https://ok.example" in highlighted


def test_is_wildcard_token_behavior():
    """Wildcard detection should trigger on '*', '*.example', and hosts containing '*'."""
    assert is_wildcard_token("*") is True
    assert is_wildcard_token("*.example.com") is True
    assert is_wildcard_token("https://*.cdn.com") is True
    assert is_wildcard_token("https://cdn.com") is False
    assert is_wildcard_token("'self'") is False


def test_problems_list_when_default_src_present():
    """Missing-directive should NOT be included when default-src exists."""
    pols = [
        Policy(name="default-src", items=[SourceItem(raw="'self'", normalized="'self'")]),
        Policy(name="script-src", items=[SourceItem(raw="'self'", normalized="'self'")]),
    ]
    res = _mk_result(
        csp_raw="default-src 'self'; script-src 'self';",
        warnings={"unsafe_inline": False, "unsafe_eval": False},
        policies=pols,
    )
    lr = LatexRenderer(lang="en")
    probs = lr._problems_list(res)
    assert "missing-directive" not in probs


def test_problems_list_when_only_unsafe_inline():
    """Only the 'unsafe' bucket should appear when unsafe-inline is present alone."""
    pols = [Policy(name="default-src"), Policy(name="script-src")]
    res = _mk_result(
        csp_raw="default-src 'self'; script-src 'unsafe-inline';",
        warnings={"unsafe_inline": True},
        policies=pols,
    )
    lr = LatexRenderer(lang="en")
    probs = lr._problems_list(res)
    assert probs == ["unsafe"]
