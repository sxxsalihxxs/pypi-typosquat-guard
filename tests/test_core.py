import pytest

from typosquat_guard.core import (
    find_typosquat,
    load_allowlist,
    normalize_name,
    osa_distance,
    parse_requirements_txt,
    scan_files,
)

ALLOW = load_allowlist()


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Requests", "requests"),
        ("python_dateutil", "python-dateutil"),
        ("zope.interface", "zope-interface"),
        ("Foo__.-Bar", "foo-bar"),
    ],
)
def test_normalize_name_follows_pep503(raw, expected):
    assert normalize_name(raw) == expected


def test_transposition_counts_as_one_edit():
    assert osa_distance("reqeusts", "requests") == 1
    assert osa_distance("abc", "abc") == 0
    assert osa_distance("", "abc") == 3


@pytest.mark.parametrize(
    "name, target, risk, technique",
    [
        ("reqeusts", "requests", "HIGH", "edit-distance"),
        ("numpi", "numpy", "HIGH", "edit-distance"),
        ("eequests", "requests", "HIGH", "edit-distance"),  # first-letter typo
        ("djang0", "django", "HIGH", "homoglyph"),
        ("beautiful-soup4", "beautifulsoup4", "HIGH", "separator"),
        ("python-requests", "requests", "MEDIUM", "affix"),
        ("flask-py", "flask", "MEDIUM", "affix"),
        ("requests2", "requests", "MEDIUM", "affix"),
        ("scikit-lern", "scikit-learn", "HIGH", "edit-distance"),
        ("matplotlb", "matplotlib", "HIGH", "edit-distance"),
        ("sqlalchemyy", "sqlalchemy", "HIGH", "edit-distance"),
        ("scikit-lrn", "scikit-learn", "MEDIUM", "edit-distance"),
        ("djangorestfrmwrk", "djangorestframework", "LOW", "edit-distance"),
    ],
)
def test_detects_typosquats(name, target, risk, technique):
    f = find_typosquat(name, ALLOW)
    assert f is not None
    assert (f.similar_to, f.risk, f.technique) == (target, risk, technique)


@pytest.mark.parametrize(
    "name",
    [
        "requests",
        "Flask",
        "pytest-cov",
        "pytest-mock",
        "numba",
        "black",
        "tox",
        "flask-login",
        "django-cors-headers",
        "my-internal-lib",
    ],
)
def test_does_not_flag_legit_or_unrelated_packages(name):
    assert find_typosquat(name, ALLOW) is None


def test_parse_requirements_handles_real_world_syntax(tmp_path):
    (tmp_path / "base.txt").write_text("Django>=4.2\n")
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comment\n"
        "-r base.txt\n"
        "--index-url https://example.org/simple\n"
        "-e git+https://example.org/repo.git#egg=thing\n"
        "requests[socks]==2.31.0  # inline comment\n"
        "numpy ; python_version >= '3.9'\n"
        "pkg @ https://example.org/pkg.whl\n"
        "\n"
    )
    names = [r.name for r in parse_requirements_txt(str(req))]
    assert names == ["django", "requests", "numpy", "pkg"]


def test_recursive_includes_do_not_loop(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nflask\n")
    (tmp_path / "b.txt").write_text("-r a.txt\nrequests\n")
    assert [r.name for r in parse_requirements_txt(str(tmp_path / "a.txt"))] == ["requests", "flask"]


def test_scan_files_reports_location_and_respects_ignore(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask\nreqeusts\nnumpi\nreqeusts\n")
    _, findings = scan_files([str(req)], ALLOW)
    assert [(f.package, f.line) for f in findings] == [("reqeusts", 2), ("numpi", 3)]

    _, findings = scan_files([str(req)], ALLOW, ignore=["numpi"])
    assert [f.package for f in findings] == ["reqeusts"]


def test_custom_allowlist_is_merged(tmp_path):
    extra = tmp_path / "allow.txt"
    extra.write_text("acme-internal-sdk  # our private package\n")
    allow = load_allowlist([str(extra)])
    assert "acme-internal-sdk" in allow and "requests" in allow
    assert find_typosquat("acme-internal-skd", allow).similar_to == "acme-internal-sdk"
