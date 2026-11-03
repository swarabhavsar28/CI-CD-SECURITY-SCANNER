"""Data model for scan results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}  # lower rank = more severe

CATEGORIES = ["secrets", "misconfig", "versions"]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int | None
    message: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, len(SEVERITIES))


@dataclass
class Report:
    target: str
    scanned_at: str
    files: list[str]
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        counts["total"] = len(self.findings)
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.file, f.line or 0, f.rule_id))

    def has_findings_at_or_above(self, severity: str) -> bool:
        threshold = SEVERITY_RANK[severity]
        return any(f.rank <= threshold for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        from . import __version__

        return {
            "tool": {"name": "cicd-scanner", "version": __version__},
            "target": self.target,
            "scanned_at": self.scanned_at,
            "files": list(self.files),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": list(self.errors),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Report":
        allowed = Finding.__dataclass_fields__
        findings = [Finding(**{k: v for k, v in item.items() if k in allowed})
                    for item in data.get("findings", [])]
        return cls(
            target=data.get("target", ""),
            scanned_at=data.get("scanned_at", ""),
            files=list(data.get("files", [])),
            findings=findings,
            errors=list(data.get("errors", [])),
        )
