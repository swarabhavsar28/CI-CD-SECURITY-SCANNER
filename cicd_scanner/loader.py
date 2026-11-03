"""Turn a target (GitHub URL or local path) into a list of workflow files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .github_api import GitHubError, github_get, resolve_token

WORKFLOW_SUFFIXES = (".yml", ".yaml")

GITHUB_URL_RE = re.compile(
    r"^(?:https?://(?:www\.)?github\.com/|git@github\.com:)"
    r"(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?"
    r"(?:/(?:tree|commits?)/(?P<ref>[^\s?#]+))?/?(?:[?#].*)?$"
)
SHORTHAND_RE = re.compile(r"^(?P<owner>[A-Za-z0-9][\w-]*)/(?P<repo>(?!\.\.?$)[\w.-]+?)(?:@(?P<ref>[^\s]+))?$")


class TargetError(ValueError):
    pass


@dataclass
class WorkflowFile:
    path: str  # display path, e.g. ".github/workflows/ci.yml"
    content: str


@dataclass
class GitHubTarget:
    owner: str
    repo: str
    ref: str | None = None

    @property
    def label(self) -> str:
        base = f"https://github.com/{self.owner}/{self.repo}"
        return f"{base}@{self.ref}" if self.ref else base


def parse_github_target(target: str) -> GitHubTarget | None:
    match = GITHUB_URL_RE.match(target.strip()) or SHORTHAND_RE.match(target.strip())
    if not match:
        return None
    return GitHubTarget(match.group("owner"), match.group("repo"), match.group("ref"))


def resolve_target(target: str, token: str | None = None) -> tuple[str, list[WorkflowFile]]:
    """Return ``(label, files)`` for a local path or GitHub repository."""
    path = Path(target).expanduser()
    if path.exists():
        return load_local(path)
    github = parse_github_target(target)
    if github:
        return load_github(github, resolve_token(token))
    raise TargetError(f"{target!r} is neither an existing path nor a GitHub repository URL")


def load_local(path: Path) -> tuple[str, list[WorkflowFile]]:
    path = path.resolve()
    if path.is_file():
        if path.suffix.lower() not in WORKFLOW_SUFFIXES:
            raise TargetError(f"{path} is not a .yml/.yaml file")
        return str(path), [WorkflowFile(path.name, path.read_text(encoding="utf-8", errors="replace"))]

    if (path / ".github" / "workflows").is_dir():
        root, workflows_dir = path, path / ".github" / "workflows"
    elif path.name == "workflows" and path.parent.name == ".github":
        root, workflows_dir = path.parent.parent, path
    else:
        raise TargetError(f"no .github/workflows directory found under {path}")

    files = []
    for candidate in sorted(workflows_dir.iterdir()):
        if candidate.is_file() and candidate.suffix.lower() in WORKFLOW_SUFFIXES:
            display = candidate.relative_to(root).as_posix()
            files.append(WorkflowFile(display, candidate.read_text(encoding="utf-8", errors="replace")))
    return str(root), files


def load_github(target: GitHubTarget, token: str | None) -> tuple[str, list[WorkflowFile]]:
    params = {"ref": target.ref} if target.ref else None
    listing_url = f"/repos/{target.owner}/{target.repo}/contents/.github/workflows"
    try:
        listing = github_get(listing_url, token, params=params).json()
    except GitHubError as exc:
        if "404" in str(exc):
            raise TargetError(
                f"{target.owner}/{target.repo} was not found or has no .github/workflows directory "
                "(private repositories need --token or GITHUB_TOKEN)"
            ) from exc
        raise TargetError(str(exc)) from exc

    if not isinstance(listing, list):
        raise TargetError(f".github/workflows in {target.owner}/{target.repo} is not a directory")

    files = []
    for entry in sorted(listing, key=lambda item: item.get("name", "")):
        name = entry.get("name", "")
        if entry.get("type") != "file" or not name.lower().endswith(WORKFLOW_SUFFIXES):
            continue
        try:
            raw = github_get(entry["url"], token, accept="application/vnd.github.raw+json")
        except GitHubError as exc:
            raise TargetError(f"failed to download {name}: {exc}") from exc
        files.append(WorkflowFile(f".github/workflows/{name}", raw.text))
    return target.label, files
