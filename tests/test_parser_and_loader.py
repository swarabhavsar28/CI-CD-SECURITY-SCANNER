from pathlib import Path

import pytest

from cicd_scanner.loader import TargetError, load_local, parse_github_target, resolve_target
from cicd_scanner.yaml_parser import parse_workflow


def test_on_key_is_not_turned_into_boolean():
    data, error = parse_workflow("on:\n  push:\n  pull_request_target:\njobs: {}\n")
    assert error is None
    assert "on" in data and True not in data
    assert set(data["on"]) == {"push", "pull_request_target"}


def test_true_false_still_parse_as_booleans_but_yes_no_do_not():
    data, _ = parse_workflow("a: true\nb: FALSE\nc: yes\nd: no\n")
    assert data["a"] is True and data["b"] is False
    assert data["c"] == "yes" and data["d"] == "no"


def test_line_numbers_are_tracked_for_keys_and_steps(make_workflow):
    wf = make_workflow(
        "name: x\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo hi\n"
    )
    assert wf.data.line_of("jobs") == 3
    job = dict(wf.jobs())["build"]
    steps = list(wf.steps(job))
    assert steps[0].line_of("uses") == 7
    assert steps[1].line_of("run") == 8


def test_parse_error_is_reported(make_workflow):
    wf = make_workflow("jobs:\n  a: [unclosed\n")
    assert wf.data is None
    assert wf.parse_error


@pytest.mark.parametrize(
    "target, expected",
    [
        ("https://github.com/pallets/flask", ("pallets", "flask", None)),
        ("https://github.com/pallets/flask.git", ("pallets", "flask", None)),
        ("git@github.com:pallets/flask.git", ("pallets", "flask", None)),
        ("https://github.com/pallets/flask/tree/2.3.x", ("pallets", "flask", "2.3.x")),
        ("pallets/flask", ("pallets", "flask", None)),
        ("pallets/flask@main", ("pallets", "flask", "main")),
    ],
)
def test_parse_github_target(target, expected):
    parsed = parse_github_target(target)
    assert (parsed.owner, parsed.repo, parsed.ref) == expected


@pytest.mark.parametrize("target", ["./relative/path", "../up", "C:/not/a/repo", "plain-words", "https://gitlab.com/a/b"])
def test_non_github_targets_are_rejected(target):
    assert parse_github_target(target) is None


def test_load_local_repo_root_finds_workflows(examples_dir):
    label, files = load_local(examples_dir / "vulnerable-repo")
    assert {f.path for f in files} == {
        ".github/workflows/broken.yml",
        ".github/workflows/deploy.yml",
        ".github/workflows/pr-build.yml",
    }


def test_load_local_accepts_workflows_dir_and_single_file(examples_dir):
    _, files = load_local(examples_dir / "clean-repo" / ".github" / "workflows")
    assert [f.path for f in files] == [".github/workflows/ci.yml"]
    _, files = load_local(examples_dir / "clean-repo" / ".github" / "workflows" / "ci.yml")
    assert [f.path for f in files] == ["ci.yml"]


def test_directory_without_workflows_raises(tmp_path: Path):
    with pytest.raises(TargetError):
        load_local(tmp_path)


def test_unresolvable_target_raises():
    with pytest.raises(TargetError):
        resolve_target("definitely not a repo or path")
