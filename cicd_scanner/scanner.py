"""Orchestrates loading workflows and running every rule over them."""

from __future__ import annotations

from datetime import datetime, timezone

from .loader import WorkflowFile, resolve_target
from .models import Finding, Report
from .rules import RULES, ScanOptions
from .workflow import Workflow


def scan_files(target_label: str, files: list[WorkflowFile], options: ScanOptions | None = None) -> Report:
    options = options or ScanOptions()
    report = Report(
        target=target_label,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        files=[f.path for f in files],
        findings=[],
    )

    for wf_file in files:
        workflow = Workflow(wf_file.path, wf_file.content)
        if workflow.parse_error:
            report.findings.append(Finding(
                rule_id="WF001",
                title="Workflow could not be parsed",
                severity="LOW",
                category="misconfig",
                file=workflow.path,
                line=None,
                message="The file is not valid YAML, so structural rules were skipped for it "
                        "(secret pattern matching still ran on the raw text).",
                evidence=workflow.parse_error.splitlines()[0][:200],
                remediation="Fix the YAML syntax; GitHub will refuse to run the workflow as well.",
            ))
        for rule in RULES:
            try:
                report.findings.extend(rule(workflow, options))
            except Exception as exc:  # a broken rule must not take down the whole scan
                report.errors.append(f"{rule.__module__.rsplit('.', 1)[-1]} rule failed on {workflow.path}: {exc}")
    report.errors.extend(sorted(options.warnings))
    return report


def scan(target: str, *, token: str | None = None, check_latest: bool = False) -> Report:
    """Scan a local path or GitHub repository URL. Raises ``TargetError`` if it cannot be loaded."""
    label, files = resolve_target(target, token)
    options = ScanOptions(check_latest=check_latest, token=token)
    return scan_files(label, files, options)
