"""Rules for common workflow misconfigurations."""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding
from ..workflow import Workflow, describe_step

CATEGORY = "misconfig"

EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)

# Event payload fields an outside contributor controls. Interpolating them into a
# shell script or inline JavaScript lets them inject commands.
UNTRUSTED_CONTEXTS = [
    r"github\.event\.issue\.(?:title|body)",
    r"github\.event\.pull_request\.(?:title|body)",
    r"github\.event\.pull_request\.head\.(?:ref|label)",
    r"github\.event\.pull_request\.head\.repo\.(?:default_branch|description|homepage)",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.(?:title|body)",
    r"github\.event\.pages(?:\[\d+\]|\.\*)\.page_name",
    r"github\.event\.commits(?:\[\d+\]|\.\*)\.(?:message|author\.(?:name|email))",
    r"github\.event\.head_commit\.(?:message|author\.(?:name|email)|committer\.(?:name|email))",
    r"github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:name|email)))",
    r"github\.head_ref",
]
UNTRUSTED_CONTEXT_RE = re.compile("|".join(f"(?:{pattern})" for pattern in UNTRUSTED_CONTEXTS))

# Triggers whose runs carry the base repository's secrets and a write token, yet can be
# initiated (directly or indirectly) by people outside the repository.
PRIVILEGED_TRIGGERS = {
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "pull_request_review",
    "pull_request_review_comment",
}

UNSAFE_CHECKOUT_REF_RE = re.compile(
    r"github\.event\.pull_request\.head|github\.head_ref|github\.event\.workflow_run\.head|refs/pull/"
)
CHECKOUT_ACTION_RE = re.compile(r"^actions/checkout(?:@|$)")
PR_CHECKOUT_CMD_RE = re.compile(r"\bgh\s+pr\s+checkout\b")

REMOTE_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:bash|sh|zsh|ksh|dash|python\d*|perl|ruby|node)\b"
)

UNSECURE_COMMANDS_KEY = "ACTIONS_ALLOW_UNSECURE_COMMANDS"


def _finding(workflow: Workflow, rule_id: str, title: str, severity: str, line: int, message: str,
             evidence: str = "", remediation: str = "") -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category=CATEGORY,
                   file=workflow.path, line=line or None, message=message,
                   evidence=evidence, remediation=remediation)


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"})


def _runs_on_labels(job: dict) -> list[str]:
    runs_on = job.get("runs-on")
    if isinstance(runs_on, str):
        return [runs_on]
    if isinstance(runs_on, list):
        return [str(item) for item in runs_on]
    if isinstance(runs_on, dict):
        labels = runs_on.get("labels", [])
        return [str(labels)] if isinstance(labels, str) else [str(item) for item in labels]
    return []


# -- permissions -------------------------------------------------------------------

def _check_permissions(workflow: Workflow) -> list[Finding]:
    findings = []
    data = workflow.data
    assert data is not None

    def write_all(owner: dict, where: str) -> None:
        perms = owner.get("permissions")
        if isinstance(perms, str) and perms.strip() == "write-all":
            findings.append(_finding(
                workflow, "MIS004", "GITHUB_TOKEN granted write-all permissions", "HIGH",
                workflow.line_of(owner, "permissions"),
                f"{where} sets 'permissions: write-all', giving every step a token that can push code, "
                "publish releases, and modify issues, PRs and packages.",
                evidence="permissions: write-all",
                remediation="List only the scopes the job needs, e.g. 'permissions: {contents: read}'.",
            ))

    write_all(data, "The workflow")
    for job_name, job in workflow.jobs():
        write_all(job, f"Job '{job_name}'")

    if "permissions" not in data:
        missing = [name for name, job in workflow.jobs() if "permissions" not in job]
        if missing:
            findings.append(_finding(
                workflow, "MIS003", "No explicit permissions for GITHUB_TOKEN", "MEDIUM",
                workflow.line_of(data, "jobs") or 1,
                "Neither the workflow nor these jobs declare 'permissions', so GITHUB_TOKEN falls back to the "
                "repository default, which is often read/write on every scope: "
                + ", ".join(missing) + ".",
                evidence="jobs without permissions: " + ", ".join(missing),
                remediation="Add a top-level 'permissions:' block with the minimum scopes "
                            "(start with 'contents: read') and widen per job only where needed.",
            ))
    return findings


# -- privileged triggers -----------------------------------------------------------

def _check_privileged_triggers(workflow: Workflow, triggers: set[str]) -> list[Finding]:
    findings = []
    privileged = sorted(triggers & PRIVILEGED_TRIGGERS)
    if not privileged:
        return findings
    trigger_label = "/".join(privileged)

    for job_name, job in workflow.jobs():
        for index, step in enumerate(workflow.steps(job)):
            uses = step.get("uses")
            with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
            ref = with_block.get("ref") if with_block else None
            if isinstance(uses, str) and CHECKOUT_ACTION_RE.match(uses) and isinstance(ref, str) \
                    and UNSAFE_CHECKOUT_REF_RE.search(ref):
                findings.append(_finding(
                    workflow, "MIS001", "Untrusted pull request code checked out in privileged workflow",
                    "CRITICAL", workflow.line_of(with_block, "ref"),
                    f"Job '{job_name}', {describe_step(step, index)} checks out the pull request head while the "
                    f"workflow runs on '{trigger_label}'. That trigger executes with the base repository's "
                    "secrets and a write-capable GITHUB_TOKEN, so anything the PR author put in build scripts, "
                    "package manifests or tests runs with those privileges (a 'pwn request').",
                    evidence=f"ref: {ref}",
                    remediation="Run untrusted code under 'pull_request' instead. If the privileged trigger is "
                                "required, never check out or execute PR code in it; split the work into an "
                                "unprivileged 'pull_request' job and a 'workflow_run' job that only consumes "
                                "artifacts, and gate on labels or approvals.",
                ))
            run = step.get("run")
            if isinstance(run, str) and PR_CHECKOUT_CMD_RE.search(run):
                findings.append(_finding(
                    workflow, "MIS001", "Untrusted pull request code checked out in privileged workflow",
                    "CRITICAL", workflow.find_line("gh pr checkout", workflow.line_of(step, "run")),
                    f"Job '{job_name}', {describe_step(step, index)} runs 'gh pr checkout' while the workflow "
                    f"is triggered by '{trigger_label}', bringing untrusted PR code into a job that has the "
                    "base repository's secrets.",
                    evidence="gh pr checkout",
                    remediation="Do not check out PR code in privileged workflows; use 'pull_request' for "
                                "anything that builds or tests contributor changes.",
                ))

    if "pull_request_target" in triggers and not any(f.rule_id == "MIS001" for f in findings):
        on_line = workflow.line_of(workflow.data, "on")
        findings.append(_finding(
            workflow, "MIS002", "Workflow uses pull_request_target", "MEDIUM",
            workflow.find_line("pull_request_target", on_line),
            "'pull_request_target' runs in the context of the base branch with access to secrets and a "
            "write token, even for pull requests from forks. Every input from the PR (title, body, branch "
            "name, files) must be treated as hostile.",
            evidence="on: pull_request_target",
            remediation="Prefer 'pull_request'. Keep 'pull_request_target' only for jobs that never execute "
                        "contributor-controlled content (e.g. labelling), and restrict 'permissions'.",
        ))
    return findings


# -- per-job checks ------------------------------------------------------------------

def _check_injection(workflow: Workflow, job_name: str, step: dict, index: int, key: str,
                     text: str, line: int, privileged: bool) -> list[Finding]:
    findings = []
    for match in EXPR_RE.finditer(text):
        expression = match.group(1)
        context = UNTRUSTED_CONTEXT_RE.search(expression)
        if not context:
            continue
        snippet = match.group(0)
        findings.append(_finding(
            workflow, "MIS005", "Untrusted input interpolated into script (expression injection)",
            "CRITICAL" if privileged else "HIGH",
            workflow.find_line(snippet.split("\n")[0][:60], line),
            f"Job '{job_name}', {describe_step(step, index)} expands '{context.group(0)}' directly inside "
            f"'{key}:'. The value is attacker-controlled and is substituted before the shell/JS runs, so a "
            "crafted title, body or branch name can execute arbitrary commands on the runner"
            + (" with access to secrets and a write token." if privileged else "."),
            evidence=snippet.strip(),
            remediation="Pass the value through an environment variable and reference it as \"$VAR\" "
                        "(shell) or process.env.VAR (JavaScript) instead of expanding it in the script body.",
        ))
    return findings


def _check_unsecure_commands(workflow: Workflow, node: Any, findings: list[Finding], where: str) -> None:
    if isinstance(node, dict):
        env = node.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if str(key).upper() == UNSECURE_COMMANDS_KEY and _truthy(value):
                    line = workflow.line_of(env, key)
                    findings.append(_finding(
                        workflow, "MIS006", "Deprecated unsecure workflow commands enabled", "HIGH", line,
                        f"{where} sets {UNSECURE_COMMANDS_KEY}=true, re-enabling the 'set-env' and "
                        "'add-path' commands GitHub disabled because any logged output can use them to "
                        "modify the environment of later steps.",
                        evidence=workflow.raw_line(line).strip(),
                        remediation="Remove the variable and write to $GITHUB_ENV / $GITHUB_PATH instead.",
                    ))


def _check_job(workflow: Workflow, job_name: str, job: dict, triggers: set[str]) -> list[Finding]:
    findings = []
    privileged = bool(triggers & PRIVILEGED_TRIGGERS)

    labels = _runs_on_labels(job)
    if any("self-hosted" in label.lower() for label in labels) and \
            triggers & {"pull_request", "pull_request_target"}:
        findings.append(_finding(
            workflow, "MIS008", "Self-hosted runner exposed to pull requests", "MEDIUM",
            workflow.line_of(job, "runs-on"),
            f"Job '{job_name}' runs on a self-hosted runner in a workflow triggered by pull requests. On a "
            "public repository, a fork PR can execute arbitrary code on your infrastructure; persistent "
            "runners also keep state between jobs.",
            evidence="runs-on: " + ", ".join(labels),
            remediation="Use GitHub-hosted runners for PR workflows, or restrict self-hosted runners to "
                        "trusted events and ephemeral, isolated machines.",
        ))

    if isinstance(job.get("secrets"), str) and job["secrets"].strip() == "inherit":
        findings.append(_finding(
            workflow, "MIS009", "All secrets passed to reusable workflow", "LOW",
            workflow.line_of(job, "secrets"),
            f"Job '{job_name}' calls a reusable workflow with 'secrets: inherit', exposing every "
            "repository/organization secret to it rather than just the ones it needs.",
            evidence="secrets: inherit",
            remediation="Pass the required secrets explicitly under 'secrets:'.",
        ))

    _check_unsecure_commands(workflow, job, findings, f"Job '{job_name}'")

    for index, step in enumerate(workflow.steps(job)):
        _check_unsecure_commands(workflow, step, findings, f"Job '{job_name}', {describe_step(step, index)}")

        run = step.get("run")
        if isinstance(run, str):
            run_line = workflow.line_of(step, "run")
            findings.extend(_check_injection(workflow, job_name, step, index, "run", run, run_line, privileged))
            for text in run.splitlines():
                if REMOTE_PIPE_RE.search(text):
                    findings.append(_finding(
                        workflow, "MIS007", "Remote script piped straight into a shell", "MEDIUM",
                        workflow.find_line(text.strip()[:50], run_line),
                        f"Job '{job_name}', {describe_step(step, index)} downloads a script and executes it "
                        "without pinning a version or verifying a checksum, so a compromised or hijacked "
                        "host changes what runs in CI.",
                        evidence=text.strip(),
                        remediation="Download to a file, verify a checksum or signature, then execute; or "
                                    "install the tool from a pinned package/action.",
                    ))

        with_block = step.get("with")
        if isinstance(with_block, dict) and isinstance(with_block.get("script"), str):
            findings.extend(_check_injection(
                workflow, job_name, step, index, "with.script", with_block["script"],
                workflow.line_of(with_block, "script"), privileged,
            ))
    return findings


def check(workflow: Workflow, options: Any) -> list[Finding]:
    if workflow.data is None:
        return []
    triggers = workflow.triggers
    findings = _check_permissions(workflow)
    findings.extend(_check_privileged_triggers(workflow, triggers))
    _check_unsecure_commands(workflow, workflow.data, findings, "The workflow")
    for job_name, job in workflow.jobs():
        findings.extend(_check_job(workflow, job_name, job, triggers))
    return findings
