# test_highlight_csp_problems.py
import pytest
from csp_check.csp_check import pretty_csp, highlight_csp_problems, URLResult


@pytest.fixture
def sample_result_template():
    """Template URLResult with warnings dict."""
    return URLResult(
        url="https://example.com",
        requested_url="https://example.com",
        csp_raw="",
        warnings={},
        policies=[],
        deprecated_used=[],
        error=None,
    )


def test_highlight_wildcard_domain(sample_result_template):
    """Should wrap the entire wildcard domain with §R[ ]R§."""
    res = sample_result_template
    res.warnings = {"wildcard_sources": True}

    csp_raw = "default-src https://example.com; img-src *.evil.com; script-src 'self';"
    formatted = pretty_csp(csp_raw)
    highlighted = highlight_csp_problems(formatted, res)

    # Ensure entire wildcard domain is surrounded, not just the star
    assert "§R[*.evil.com]R§" in highlighted
    # other parts should remain unchanged
    assert "'self'" in highlighted


def test_highlight_unsafe_inline_and_eval(sample_result_template):
    """Should highlight both unsafe-inline and unsafe-eval keywords."""
    res = sample_result_template
    res.warnings = {"unsafe_inline": True, "unsafe_eval": True}

    csp_raw = "script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self';"
    formatted = pretty_csp(csp_raw)
    highlighted = highlight_csp_problems(formatted, res)

    # Both unsafe keywords should be wrapped with §R[...]R§
    assert "§R['unsafe-inline']R§" in highlighted
    assert "§R['unsafe-eval']R§" in highlighted
    # Safe items remain unmodified
    assert "'self'" in highlighted
