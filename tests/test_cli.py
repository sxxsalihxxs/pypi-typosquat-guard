import json

from typosquat_guard.cli import main
from typosquat_guard.report import COMMENT_MARKER


def write(tmp_path, text):
    p = tmp_path / "requirements.txt"
    p.write_text(text)
    return str(p)


def test_clean_file_exits_zero(tmp_path, capsys):
    assert main([write(tmp_path, "requests\nflask\n")]) == 0
    assert "No suspicious packages" in capsys.readouterr().out


def test_high_finding_fails_by_default(tmp_path):
    assert main([write(tmp_path, "reqeusts\n")]) == 1


def test_fail_on_threshold(tmp_path):
    path = write(tmp_path, "python-requests\n")  # MEDIUM
    assert main([path]) == 0
    assert main([path, "--fail-on", "medium"]) == 1
    assert main([path, "--fail-on", "never"]) == 0


def test_json_output(tmp_path, capsys):
    main([write(tmp_path, "numpi\n"), "--format", "json", "--fail-on", "never"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["similar_to"] == "numpy"


def test_markdown_report_to_file(tmp_path):
    out = tmp_path / "report.md"
    main([write(tmp_path, "djang0\n"), "--format", "markdown", "--out", str(out), "--fail-on", "never"])
    md = out.read_text()
    assert md.startswith(COMMENT_MARKER)
    assert "`djang0`" in md and "`django`" in md


def test_legacy_file_flag_still_works(tmp_path):
    assert main(["--file", write(tmp_path, "flask\n")]) == 0


def test_missing_file_returns_2(tmp_path, capsys):
    assert main([str(tmp_path / "nope.txt")]) == 2
    assert "error" in capsys.readouterr().err
