"""Rules for outdated, unpinned and known-vulnerable action references."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..github_api import GitHubError, github_get
from ..models import Finding
from ..workflow import Workflow, describe_step

CATEGORY = "versions"
DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "known_actions.json"

USES_RE = re.compile(r"^(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?P<path>/[^@\s]*)?@(?P<ref>\S+)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+.].*)?$")
COMMENT_VERSION_RE = re.compile(r"#\s*(?:tag=|version=|ratchet:\S+@)?\s*v?(\d+(?:\.\d+){0,2})\b")
RANGE_CLAUSE_RE = re.compile(r"^(<=|>=|<|>)\s*v?(\d+(?:\.\d+){0,2})$")

INF = float("inf")
Version = tuple[float, float, float]


@lru_cache(maxsize=1)
def load_known_actions() -> dict[str, Any]:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


# -- version helpers -----------------------------------------------------------------

def parse_version(ref: str) -> Version | None:
    """``v4`` -> (4, inf, inf): a floating tag tracks the newest release of that major."""
    match = VERSION_RE.match(ref.strip())
    if not match:
        return None
    return tuple(int(group) if group is not None else INF for group in match.groups())  # type: ignore[return-value]


def _parse_bound(text: str) -> Version:
    parts = [int(part) for part in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def version_in_range(version: Version, spec: str) -> bool:
    """Evaluate a comma-separated range such as ``>=4.0.0,<4.1.7``."""
    for clause in spec.split(","):
        match = RANGE_CLAUSE_RE.match(clause.strip())
        if not match:
            return False
        op, bound = match.group(1), _parse_bound(match.group(2))
        ok = {"<": version < bound, "<=": version <= bound, ">": version > bound, ">=": version >= bound}[op]
        if not ok:
            return False
    return True


def parse_docker_ref(ref: str) -> tuple[str, str | None, str | None]:
    """Split ``image[:tag][@digest]`` (with or without a ``docker://`` prefix)."""
    body = ref[len("docker://"):] if ref.startswith("docker://") else ref
    digest = None
    if "@" in body:
        body, digest = body.split("@", 1)
    tag = None
    if body.rfind(":") > body.rfind("/"):
        body, tag = body.rsplit(":", 1)
    return body, tag, digest


def _latest_major_live(repo: str, options: Any) -> int | None:
    cache = options.cache.setdefault("latest_major", {})
    if repo in cache:
        return cache[repo]
    major = None
    try:
        release = github_get(f"/repos/{repo}/releases/latest", options.token).json()
        version = parse_version(str(release.get("tag_name", "")))
        if version:
            major = int(version[0])
    except GitHubError as release_error:
        try:
            tags = github_get(f"/repos/{repo}/tags", options.token, params={"per_page": 50}).json()
            versions = [parse_version(tag.get("name", "")) for tag in tags if isinstance(tag, dict)]
            valid = [version for version in versions if version]
            if valid:
                major = int(max(valid)[0])
        except GitHubError as tag_error:
            reason = tag_error if "rate limit" in str(tag_error) else release_error
            options.warnings.add(
                f"--check-latest: could not fetch latest release of {repo} ({reason}); used bundled snapshot"
            )
    cache[repo] = major
    return major


# -- reference checks ------------------------------------------------------------------

def _finding(workflow: Workflow, rule_id: str, title: str, severity: str, line: int, message: str,
             evidence: str, remediation: str) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category=CATEGORY,
                   file=workflow.path, line=line or None, message=message,
                   evidence=evidence, remediation=remediation)


def _check_docker_image(workflow: Workflow, image: str, line: int, where: str) -> list[Finding]:
    _, tag, digest = parse_docker_ref(image)
    if digest:
        return []
    if tag and tag != "latest":
        return []
    return [_finding(
        workflow, "VER007", "Container image not pinned to a version", "MEDIUM", line,
        f"{where} uses image '{image}' " + ("with the floating 'latest' tag" if tag else "without a tag")
        + ", so each run pulls whatever the registry currently serves.",
        image,
        "Pin to a specific tag, ideally with a digest: image:1.2.3@sha256:<digest>.",
    )]


def _check_action_ref(workflow: Workflow, uses: str, line: int, where: str, options: Any) -> list[Finding]:
    findings: list[Finding] = []
    if uses.startswith("docker://"):
        return _check_docker_image(workflow, uses, line, where)
    if uses.startswith((".", "/")):
        return findings  # local action or reusable workflow in the same repo
    match = USES_RE.match(uses)
    if not match:
        return findings

    repo, ref = match.group("repo"), match.group("ref")
    target = uses.rsplit("@", 1)[0]  # repo plus optional sub-path, e.g. reusable workflow file
    known = load_known_actions()
    info = known["actions"].get(repo, {})
    version: Version | None = None

    if SHA_RE.match(ref):
        comment = COMMENT_VERSION_RE.search(workflow.raw_line(line).split("@", 1)[-1])
        if comment:
            version = parse_version(comment.group(1))
    elif parse_version(ref):
        version = parse_version(ref)
        findings.append(_finding(
            workflow, "VER002", "Action pinned to a tag instead of a commit SHA", "LOW", line,
            f"{where} references '{repo}' by tag '{ref}'. Tags are mutable: a maintainer or an attacker "
            "with push access can move them to different code (this is exactly what happened to "
            "tj-actions/changed-files in 2025).",
            uses,
            f"Pin to the full commit SHA of the release and keep the version as a comment: "
            f"uses: {target}@<40-char sha> # {ref}",
        ))
    else:
        release_branch = ref in info.get("release_branches", [])
        findings.append(_finding(
            workflow, "VER001", "Action pinned to a mutable branch", "LOW" if release_branch else "HIGH", line,
            (f"'{ref}' is the documented release channel for {repo}, but it is still a branch that moves "
             "whenever the maintainers push." if release_branch else
             f"{where} references '{repo}' by branch/ref '{ref}'. Every push to that ref immediately changes "
             "what runs in your CI, without any change on your side, so one compromised maintainer account "
             "compromises your pipeline."),
            uses,
            f"Pin to a full commit SHA: uses: {target}@<40-char sha> # <version>",
        ))

    if info.get("deprecated"):
        findings.append(_finding(
            workflow, "VER006", "Deprecated or archived action", "MEDIUM", line,
            f"{where} uses '{repo}', which is no longer maintained. {info['deprecated']}",
            uses,
            "Switch to the maintained replacement.",
        ))

    if version is None:
        return findings

    major = int(version[0])
    vulnerable = False
    for entry in known.get("vulnerable", []):
        if entry["action"] == repo and version_in_range(version, entry["affected"]):
            vulnerable = True
            findings.append(_finding(
                workflow, "VER005", f"Known vulnerable action version ({entry['advisory']})",
                entry.get("severity", "HIGH"), line,
                f"{where} uses '{repo}' at '{ref}', which falls in the affected range "
                f"'{entry['affected']}'. {entry['summary']}",
                uses,
                entry["fix"],
            ))
    if vulnerable:
        return findings  # the advisory already says to upgrade; skip the generic staleness checks

    min_major = info.get("min_supported_major")
    if min_major is not None and major < min_major:
        findings.append(_finding(
            workflow, "VER003", "Unsupported action major version", "HIGH", line,
            f"{where} uses '{repo}' v{major}; versions before v{min_major} are retired. "
            + info.get("note", "They run on a Node.js runtime GitHub has removed from runners and no "
                               "longer receive security fixes."),
            uses,
            f"Upgrade to {repo}@v{info.get('latest_major', min_major)} and pin to its commit SHA.",
        ))
        return findings

    latest = None
    source = "bundled snapshot"
    if options.check_latest:
        live = _latest_major_live(repo, options)
        if live is not None:
            latest, source = live, "GitHub releases"
    if latest is None:
        latest = info.get("latest_major")
    if latest is not None and major < latest:
        findings.append(_finding(
            workflow, "VER004", "Newer major version of action available", "MEDIUM", line,
            f"{where} uses '{repo}' v{major}, but v{latest} is the latest major release (per {source}). "
            "Older majors typically stop receiving fixes once a new one ships.",
            uses,
            f"Upgrade to {repo}@v{latest} (review the changelog for breaking changes) and pin the commit SHA.",
        ))
    return findings


def check(workflow: Workflow, options: Any) -> list[Finding]:
    if workflow.data is None:
        return []
    findings: list[Finding] = []
    for job_name, job in workflow.jobs():
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            findings.extend(_check_action_ref(
                workflow, job_uses.strip(), workflow.line_of(job, "uses"), f"Job '{job_name}'", options))

        container = job.get("container")
        if isinstance(container, str):
            findings.extend(_check_docker_image(workflow, container, workflow.line_of(job, "container"),
                                                f"Job '{job_name}' container"))
        elif isinstance(container, dict) and isinstance(container.get("image"), str):
            findings.extend(_check_docker_image(workflow, container["image"], workflow.line_of(container, "image"),
                                                f"Job '{job_name}' container"))

        services = job.get("services")
        if isinstance(services, dict):
            for service_name, service in services.items():
                if isinstance(service, dict) and isinstance(service.get("image"), str):
                    findings.extend(_check_docker_image(
                        workflow, service["image"], workflow.line_of(service, "image"),
                        f"Job '{job_name}' service '{service_name}'"))

        for index, step in enumerate(workflow.steps(job)):
            uses = step.get("uses")
            if isinstance(uses, str):
                findings.extend(_check_action_ref(
                    workflow, uses.strip(), workflow.line_of(step, "uses"),
                    f"Job '{job_name}', {describe_step(step, index)}", options))
    return findings
