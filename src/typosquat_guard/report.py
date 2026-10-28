from __future__ import annotations

import json
from collections.abc import Sequence

from typosquat_guard.core import Finding, Requirement

# Hidden marker so the GitHub workflow can update its own comment instead of adding new ones.
COMMENT_MARKER = "<!-- typosquat-guard-report -->"

RISK_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}


def _counts(findings: Sequence[Finding]) -> str:
    c = {r: sum(1 for f in findings if f.risk == r) for r in ("HIGH", "MEDIUM", "LOW")}
    return f"High: {c['HIGH']} | Medium: {c['MEDIUM']} | Low: {c['LOW']}"


def render_markdown(files: Sequence[str], reqs: list[Requirement], findings: list[Finding]) -> str:
    lines = [
        COMMENT_MARKER,
        "## 🛡️ Typosquat Guard report",
        "",
        f"**Scanned:** {', '.join(f'`{p}`' for p in files)} — {len({r.name for r in reqs})} packages  ",
        f"**{_counts(findings)}**",
        "",
    ]
    if not findings:
        lines.append("✅ No suspicious packages found.")
        return "\n".join(lines) + "\n"

    lines += [
        "| Risk | Package | Looks like | Technique | Why | Location |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            f"| {RISK_ICON[f.risk]} **{f.risk}** | `{f.package}` | `{f.similar_to}` | {f.technique} "
            f"| {f.reason} | `{f.file}:{f.line}` |"
        )
    lines += [
        "",
        "> Verify each package on https://pypi.org before merging. If a flagged package is legitimate, "
        "add it to your allowlist or pass `--ignore <name>`.",
    ]
    return "\n".join(lines) + "\n"


def render_json(files: Sequence[str], reqs: list[Requirement], findings: list[Finding]) -> str:
    return (
        json.dumps(
            {
                "files": list(files),
                "packages": sorted({r.name for r in reqs}),
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        )
        + "\n"
    )


def render_text(files: Sequence[str], reqs: list[Requirement], findings: list[Finding]) -> str:
    lines = [f"Scanned {len({r.name for r in reqs})} packages in {', '.join(files)} ({_counts(findings)})"]
    for f in findings:
        lines.append(f"  [{f.risk:<6}] {f.package:<24} -> {f.similar_to:<20} {f.reason} ({f.file}:{f.line})")
    if not findings:
        lines.append("  No suspicious packages found.")
    return "\n".join(lines) + "\n"


def render_slack(files: Sequence[str], findings: list[Finding]) -> str:
    head = f":rotating_light: Typosquat Guard: {len(findings)} suspicious package(s) in {', '.join(files)}"
    body = [f"• *{f.risk}* `{f.package}` looks like `{f.similar_to}` ({f.reason})" for f in findings]
    return "\n".join([head, *body])


RENDERERS = {"markdown": render_markdown, "json": render_json, "text": render_text}
