from __future__ import annotations

import argparse
import sys

from typosquat_guard import __version__
from typosquat_guard.core import RISK_ORDER, load_allowlist, scan_files
from typosquat_guard.report import RENDERERS, render_slack
from typosquat_guard.slack import send_slack_alert


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="typosquat-guard",
        description="Detect typosquatted / look-alike packages in Python requirements files.",
    )
    ap.add_argument("files", nargs="*", help="requirements file(s) to scan")
    ap.add_argument("--file", action="append", default=[], help=argparse.SUPPRESS)
    ap.add_argument(
        "--allowlist",
        action="append",
        default=[],
        metavar="PATH",
        help="extra allowlist file, merged with the built-in one (repeatable)",
    )
    ap.add_argument(
        "--no-default-allowlist", action="store_true", help="use only the allowlists passed with --allowlist"
    )
    ap.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="NAME",
        help="package name to never flag (repeatable)",
    )
    ap.add_argument(
        "--format", choices=sorted(RENDERERS), default="text", help="report format (default: text)"
    )
    ap.add_argument("--out", metavar="PATH", help="write the report to a file instead of stdout")
    ap.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "never"],
        default="high",
        help="exit with code 1 if a finding at or above this risk exists (default: high)",
    )
    ap.add_argument("--slack", action="store_true", help="post findings to $SLACK_WEBHOOK_URL")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    files = args.files + args.file
    if not files:
        ap.error("no requirements file given")
    if args.no_default_allowlist and not args.allowlist:
        ap.error("--no-default-allowlist requires at least one --allowlist")

    try:
        allowlist = load_allowlist(args.allowlist, include_default=not args.no_default_allowlist)
        reqs, findings = scan_files(files, allowlist, ignore=args.ignore)
    except OSError as e:
        print(f"typosquat-guard: error: {e}", file=sys.stderr)
        return 2

    report = RENDERERS[args.format](files, reqs, findings)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Wrote {args.out} (packages={len({r.name for r in reqs})}, findings={len(findings)})")
    else:
        sys.stdout.write(report)

    if args.slack and findings:
        send_slack_alert(render_slack(files, findings))

    if args.fail_on != "never":
        level = RISK_ORDER[args.fail_on.upper()]
        if any(RISK_ORDER[f.risk] >= level for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
