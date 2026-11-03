"""Report output: JSON and a human-readable text summary."""

from __future__ import annotations

import json
import textwrap

from .models import SEVERITIES, Report

COLORS = {
    "CRITICAL": "\033[1;91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

WIDTH = 100
INDENT = "    "


def to_json(report: Report, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent)


def _wrap(text: str, prefix: str = INDENT) -> str:
    return textwrap.fill(text, width=WIDTH, initial_indent=prefix, subsequent_indent=prefix)


def render_text(report: Report, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    summary = report.summary
    lines = [
        paint("CI/CD Workflow Security Scan", BOLD),
        f"Target : {report.target}",
        f"Files  : {len(report.files)} workflow file(s)" + (" - " + ", ".join(report.files) if report.files else ""),
        f"Time   : {report.scanned_at}",
        "",
        "Summary: " + "  ".join(
            paint(f"{sev} {summary[sev]}", COLORS[sev] if summary[sev] else DIM) for sev in SEVERITIES
        ) + f"  (total {summary['total']})",
    ]

    if not report.findings:
        lines += ["", paint("No findings.", "\033[92m")]
    else:
        findings = report.sorted_findings()
        current = None
        for finding in findings:
            if finding.severity != current:
                current = finding.severity
                lines += ["", paint(f"== {current} ==", COLORS[current])]
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            lines.append(
                paint(f"[{finding.severity}]", COLORS[finding.severity]) + f" {finding.rule_id}  "
                + paint(finding.title, BOLD)
            )
            lines.append(f"{INDENT}{paint(location, DIM)}")
            lines.append(_wrap(finding.message))
            if finding.evidence:
                lines.append(f"{INDENT}Evidence   : {finding.evidence}")
            if finding.remediation:
                lines.append(_wrap("Remediation: " + finding.remediation))
            lines.append("")

    if report.errors:
        lines += ["", paint("Warnings / errors:", COLORS["MEDIUM"])]
        lines += [f"{INDENT}- {error}" for error in report.errors]

    return "\n".join(lines).rstrip() + "\n"
