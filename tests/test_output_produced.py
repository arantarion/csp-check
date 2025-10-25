import subprocess
import json


def test_json_output_file(tmp_path):
    """Check that -o test.json --format json produces a non-empty, valid JSON file."""
    output_file = tmp_path / "test.json"
    test_url = "https://example.com"

    result = subprocess.run(
        [
            "python",
            "-m",
            "csp_check.csp_check",
            "-u",
            test_url,
            "-o",
            str(output_file),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"CLI failed with output: {result.stderr or result.stdout}"

    assert output_file.exists(), "Output file was not created"
    content = output_file.read_text(encoding="utf-8").strip()
    assert content, "Output file is empty"

    # Validate that it's valid JSON
    data = json.loads(content)
    assert isinstance(data, list), "Expected JSON list structure"
    assert "requested_url" in data[0], "JSON missing expected key"


def test_text_output_file(tmp_path):
    """Check that -o test.txt --format text produces a non-empty file."""
    output_file = tmp_path / "test.txt"
    test_url = "https://example.com"

    result = subprocess.run(
        [
            "python",
            "-m",
            "csp_check.csp_check",
            "-u",
            test_url,
            "-o",
            str(output_file),
            "--format",
            "text",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"CLI failed with output: {result.stderr or result.stdout}"

    assert output_file.exists(), "Output file was not created"
    content = output_file.read_text(encoding="utf-8").strip()
    assert content, "Output file is empty"


def test_raw_output_file(tmp_path):
    """Check that -o test.txt --format raw produces a non-empty file."""
    output_file = tmp_path / "test.txt"
    test_url = "https://example.com"

    result = subprocess.run(
        [
            "python",
            "-m",
            "csp_check.csp_check",
            "-u",
            test_url,
            "-o",
            str(output_file),
            "--format",
            "raw",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"CLI failed with output: {result.stderr or result.stdout}"

    assert output_file.exists(), "Output file was not created"
    content = output_file.read_text(encoding="utf-8").strip()
    assert content, "Output file is empty"


def test_latex_output_file(tmp_path):
    """Check that -o test.tex --format latex produces a non-empty file."""
    output_file = tmp_path / "test.tex"
    test_url = "https://example.com"

    result = subprocess.run(
        [
            "python",
            "-m",
            "csp_check.csp_check",
            "-u",
            test_url,
            "-o",
            str(output_file),
            "--format",
            "latex",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"CLI failed with output: {result.stderr or result.stdout}"

    assert output_file.exists(), "Output file was not created"
    content = output_file.read_text(encoding="utf-8").strip()
    assert content, "Output file is empty"

    assert r"\finding[status=Open]" in content, "No valid LaTeX"
