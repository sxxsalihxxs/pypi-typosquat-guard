from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path

# A requirement line starts with a distribution name (PEP 508).
NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

# Characters attackers commonly swap for look-alikes.
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "!": "i", "|": "l"})

# Affixes that turn a real name into a plausible-looking fake (e.g. `python-requests`).
SQUAT_PREFIXES = ("python-", "py-")
SQUAT_SUFFIXES = ("-python", "-py", "-lib", "-dev", "-official")

RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def normalize_name(name: str) -> str:
    """Normalize a package name as PyPI does (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


@dataclass
class Requirement:
    name: str
    file: str
    line: int


def parse_requirements_txt(path: str, _seen: set[Path] | None = None) -> list[Requirement]:
    """Parse a requirements file, following `-r`/`--requirement` includes."""
    seen = _seen if _seen is not None else set()
    p = Path(path).resolve()
    if p in seen:
        return []
    seen.add(p)

    reqs: list[Requirement] = []
    with open(p, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            s = line.split(" #", 1)[0].strip()
            if not s or s.startswith("#"):
                continue
            include = re.match(r"^(?:-r|--requirement)[\s=]+(\S+)", s)
            if include:
                reqs.extend(parse_requirements_txt(str(p.parent / include.group(1)), seen))
                continue
            # Other pip options (-e, -c, --index-url, ...) are out of scope.
            if s.startswith("-"):
                continue
            m = NAME_RE.match(s)
            if m:
                reqs.append(Requirement(normalize_name(m.group(1)), str(path), lineno))
    return reqs


def osa_distance(a: str, b: str) -> int:
    """Edit distance where swapping two adjacent characters counts as one edit."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def distance_threshold(name: str) -> int:
    """Short names collide naturally, so allow fewer edits for them."""
    n = len(name)
    if n <= 4:
        return 0
    if n <= 8:
        return 1
    if n <= 14:
        return 2
    return 3


@dataclass
class Finding:
    package: str
    similar_to: str
    risk: str
    technique: str
    reason: str
    file: str = ""
    line: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def find_typosquat(name: str, allowlist: Iterable[str]) -> Finding | None:
    """Return a Finding if `name` looks like a typosquat of an allowlisted package."""
    n = normalize_name(name)
    allow = {normalize_name(a) for a in allowlist}
    if n in allow:
        return None

    deglyphed = n.translate(HOMOGLYPHS)
    if deglyphed != n and deglyphed in allow:
        return Finding(n, deglyphed, "HIGH", "homoglyph", f"look-alike characters for `{deglyphed}`")

    collapsed = n.replace("-", "")
    for good in allow:
        if collapsed == good.replace("-", ""):
            return Finding(n, good, "HIGH", "separator", f"same as `{good}` with different separators")

    for prefix in SQUAT_PREFIXES:
        if n.startswith(prefix) and n[len(prefix) :] in allow:
            good = n[len(prefix) :]
            return Finding(n, good, "MEDIUM", "affix", f"`{good}` with a `{prefix}` prefix")
    for suffix in SQUAT_SUFFIXES:
        if n.endswith(suffix) and n[: -len(suffix)] in allow:
            good = n[: -len(suffix)]
            return Finding(n, good, "MEDIUM", "affix", f"`{good}` with a `{suffix}` suffix")
    stripped = n.rstrip("0123456789")
    if stripped != n and stripped in allow:
        return Finding(n, stripped, "MEDIUM", "affix", f"`{stripped}` with a numeric suffix")

    threshold = distance_threshold(n)
    if threshold == 0:
        return None
    best: tuple[str, int] | None = None
    for good in sorted(allow):
        if abs(len(n) - len(good)) > threshold:
            continue
        d = osa_distance(n, good)
        if best is None or d < best[1]:
            best = (good, d)
    if best is None or best[1] > threshold:
        return None

    good, dist = best
    risk = "HIGH" if dist == 1 else "MEDIUM" if dist == 2 else "LOW"
    edits = "edit" if dist == 1 else "edits"
    return Finding(n, good, risk, "edit-distance", f"{dist} {edits} away from `{good}`")


def load_allowlist(paths: Iterable[str] = (), include_default: bool = True) -> set[str]:
    lines: list[str] = []
    if include_default:
        data = resources.files("typosquat_guard").joinpath("data/allowlist.txt")
        lines.extend(data.read_text(encoding="utf-8").splitlines())
    for path in paths:
        lines.extend(Path(path).read_text(encoding="utf-8").splitlines())
    return {normalize_name(s) for s in (ln.split("#", 1)[0].strip() for ln in lines) if s}


def scan_files(
    req_paths: Iterable[str], allowlist: set[str], ignore: Iterable[str] = ()
) -> tuple[list[Requirement], list[Finding]]:
    ignored = {normalize_name(i) for i in ignore}
    reqs: list[Requirement] = []
    for path in req_paths:
        reqs.extend(parse_requirements_txt(path))

    findings: list[Finding] = []
    reported: set[str] = set()
    for req in reqs:
        if req.name in ignored or req.name in reported:
            continue
        finding = find_typosquat(req.name, allowlist)
        if finding:
            finding.file, finding.line = req.file, req.line
            findings.append(finding)
            reported.add(req.name)
    findings.sort(key=lambda f: -RISK_ORDER[f.risk])
    return reqs, findings


def scan_requirements(
    req_path: str, allowlist_path: str | None = None
) -> tuple[list[Requirement], list[Finding]]:
    """Scan a single requirements file (kept for backwards compatibility)."""
    extra = [allowlist_path] if allowlist_path else []
    return scan_files([req_path], load_allowlist(extra))
