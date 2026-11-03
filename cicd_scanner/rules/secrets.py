"""Rules for exposed secrets and hardcoded credentials."""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding
from ..workflow import Workflow, describe_step

CATEGORY = "secrets"

# (rule id, title, severity, pattern). Patterns run against the raw file text, line by line.
TOKEN_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("SEC001", "AWS access key ID", "CRITICAL",
     re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("SEC002", "GitHub personal access token", "CRITICAL",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("SEC003", "Slack token", "CRITICAL",
     re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("SEC004", "Private key material", "CRITICAL",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("SEC005", "Google API key", "HIGH",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SEC006", "Stripe live secret key", "CRITICAL",
     re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("SEC007", "npm access token", "CRITICAL",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SEC008", "JSON Web Token", "HIGH",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
]

URL_CREDENTIALS_RE = re.compile(
    r"\b(?P<scheme>[a-z][a-z0-9+.-]*)://(?P<user>[^/\s:@'\"]+):(?P<password>[^/\s@'\"]+)@", re.I
)

CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"credential|private[_-]?key|client[_-]?secret|auth[_-]?key)"
)
# Keys like TOKEN_FILE or SECRET_NAME hold references, not the credential itself.
NON_SECRET_SUFFIX_RE = re.compile(
    r"(?i)[_-]?(file|path|name|url|uri|type|format|header|prefix|length|ttl|expir\w*|version)$"
)

SECRET_EXPR_RE = re.compile(r"\$\{\{\s*secrets\.")
SECRET_ECHO_RE = re.compile(r"\b(?:echo|printf|cat)\b.*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")

VALUE_HOLDER_KEYS = ("env", "with", "secrets")


def mask(value: str) -> str:
    """Show enough of a secret to identify it without reproducing it in the report."""
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    stars = "*" * min(len(value) - 8, 12)
    return value[:4] + stars + value[-4:]


def _looks_like_literal_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if len(text) < 4:
        return False
    if "${{" in text or text.startswith(("$", "%", "<", "/", "./", "~", "@")):
        return False
    if re.fullmatch(r"(?i)(true|false|null|none|yes|no|\d+)", text):
        return False
    if re.fullmatch(r"https?://[^@]*", text):
        return False
    if re.fullmatch(r"[*x#_.-]+", text, re.I):
        return False
    return True


def _env_name(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", key).upper()


def _scan_raw_patterns(workflow: Workflow) -> list[Finding]:
    findings = []
    seen: set[tuple[str, int]] = set()
    for line_no, line in enumerate(workflow.lines, start=1):
        for rule_id, title, severity, pattern in TOKEN_PATTERNS:
            match = pattern.search(line)
            if not match or (rule_id, line_no) in seen:
                continue
            seen.add((rule_id, line_no))
            findings.append(Finding(
                rule_id=rule_id,
                title=f"{title} committed in workflow",
                severity=severity,
                category=CATEGORY,
                file=workflow.path,
                line=line_no,
                message=f"A string matching the format of a {title.lower()} appears in the workflow file. "
                        "Anyone with read access to the repository (or its history) can use it.",
                evidence=mask(match.group(0)),
                remediation="Revoke and rotate the credential, then move it to an encrypted repository or "
                            "environment secret and reference it as ${{ secrets.NAME }}.",
            ))

        for match in URL_CREDENTIALS_RE.finditer(line):
            password = match.group("password")
            if "$" in password or ("SEC009", line_no) in seen:
                continue
            seen.add(("SEC009", line_no))
            findings.append(Finding(
                rule_id="SEC009",
                title="Credentials embedded in URL",
                severity="HIGH",
                category=CATEGORY,
                file=workflow.path,
                line=line_no,
                message="A URL in the workflow carries a username and password/token inline.",
                evidence=f"{match.group('scheme')}://{match.group('user')}:{mask(password)}@",
                remediation="Store the credential as a secret and inject it at runtime "
                            "(for example via an environment variable or a credential helper).",
            ))
    return findings


def _walk_for_hardcoded(workflow: Workflow, node: Any, parent_key: str | None,
                        findings: list[Finding], flagged_lines: set[int]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key)
            line = workflow.line_of(node, key)
            if (
                parent_key in VALUE_HOLDER_KEYS
                and line not in flagged_lines  # a token-format rule already reported this line
                and CREDENTIAL_KEY_RE.search(key_text)
                and not NON_SECRET_SUFFIX_RE.search(key_text)
                and _looks_like_literal_secret(value)
            ):
                findings.append(Finding(
                    rule_id="SEC010",
                    title="Hardcoded credential in workflow",
                    severity="HIGH",
                    category=CATEGORY,
                    file=workflow.path,
                    line=line,
                    message=f"'{key_text}' under '{parent_key}:' is set to a literal value "
                            "instead of a secret reference.",
                    evidence=f"{key_text}: {mask(value)}",
                    remediation=f"Move the value to a repository/environment secret and reference it as "
                                f"'{key_text}: ${{{{ secrets.{_env_name(key_text)} }}}}'.",
                ))
            _walk_for_hardcoded(workflow, value, key_text, findings, flagged_lines)
    elif isinstance(node, list):
        for item in node:
            _walk_for_hardcoded(workflow, item, parent_key, findings, flagged_lines)


def _scan_secret_echo(workflow: Workflow) -> list[Finding]:
    findings = []
    for job_name, job in workflow.jobs():
        for index, step in enumerate(workflow.steps(job)):
            run = step.get("run")
            if not isinstance(run, str) or not SECRET_EXPR_RE.search(run):
                continue
            run_line = workflow.line_of(step, "run")
            for text in run.splitlines():
                match = SECRET_ECHO_RE.search(text)
                if not match:
                    continue
                findings.append(Finding(
                    rule_id="SEC011",
                    title="Secret written to job output",
                    severity="MEDIUM",
                    category=CATEGORY,
                    file=workflow.path,
                    line=workflow.find_line(text.strip()[:40], run_line),
                    message=f"Job '{job_name}', {describe_step(step, index)} prints a secret with a shell "
                            "command. GitHub masks exact matches in logs, but transformed output (base64, "
                            "split strings, JSON) leaks, and the value can end up in artifacts or summaries.",
                    evidence=text.strip(),
                    remediation="Never echo secrets. Pass them to tools via environment variables or files "
                                "with restricted permissions.",
                ))
    return findings


def check(workflow: Workflow, options: Any) -> list[Finding]:
    findings = _scan_raw_patterns(workflow)
    if workflow.data is not None:
        flagged_lines = {f.line for f in findings if f.line}
        _walk_for_hardcoded(workflow, workflow.data, None, findings, flagged_lines)
        findings.extend(_scan_secret_echo(workflow))
    return findings
