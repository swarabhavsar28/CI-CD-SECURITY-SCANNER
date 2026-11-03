"""Command-line interface: ``cicd-scan scan <target>`` and ``cicd-scan serve``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .loader import TargetError
from .models import SEVERITIES
from .report import render_text, to_json

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cicd-scan",
        description="Scan GitHub Actions workflows for exposed secrets, risky configuration "
                    "and outdated or vulnerable action versions.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a GitHub repository URL or a local checkout")
    scan.add_argument("target", help="repo URL (https://github.com/owner/repo[/tree/ref]), owner/repo, "
                                     "or a local path (repo root, .github/workflows dir, or a single file)")
    scan.add_argument("-o", "--output", metavar="FILE", help="write the JSON report to FILE")
    scan.add_argument("--format", choices=["text", "json"], default="text",
                      help="what to print to stdout (default: text)")
    scan.add_argument("--fail-on", choices=[s.lower() for s in SEVERITIES] + ["none"], default="high",
                      help="exit with status 1 if any finding is at or above this severity (default: high)")
    scan.add_argument("--token", help="GitHub token for private repos / higher rate limits "
                                      "(defaults to $GITHUB_TOKEN or $GH_TOKEN)")
    scan.add_argument("--check-latest", action="store_true",
                      help="query the GitHub API for each action's latest release instead of the bundled snapshot")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colours in text output")

    serve = subparsers.add_parser("serve", help="start the web UI for browsing reports")
    serve.add_argument("--reports-dir", default="reports", help="directory holding JSON reports (default: ./reports)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=5000)
    serve.add_argument("--debug", action="store_true")
    return parser


def _use_color(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def run_scan(args: argparse.Namespace) -> int:
    from .scanner import scan

    try:
        report = scan(args.target, token=args.token, check_latest=args.check_latest)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(to_json(report), encoding="utf-8")

    if args.format == "json":
        print(to_json(report))
    else:
        print(render_text(report, color=_use_color(args.no_color)), end="")
        if args.output:
            print(f"JSON report written to {args.output}")

    if args.fail_on != "none" and report.has_findings_at_or_above(args.fail_on.upper()):
        return EXIT_FINDINGS
    return EXIT_OK


def run_serve(args: argparse.Namespace) -> int:
    try:
        from .web.app import create_app
    except ImportError:
        print("error: the web UI needs Flask - install it with: pip install flask", file=sys.stderr)
        return EXIT_ERROR

    app = create_app(args.reports_dir)
    print(f"Reports directory: {Path(args.reports_dir).resolve()}")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "serve":
        return run_serve(args)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
