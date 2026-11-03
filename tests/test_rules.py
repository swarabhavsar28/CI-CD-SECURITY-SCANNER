import json

import pytest

from cicd_scanner.models import Report
from cicd_scanner.report import render_text, to_json
from cicd_scanner.rules.secrets import mask
from cicd_scanner.rules.versions import parse_docker_ref, parse_version, version_in_range
from cicd_scanner.scanner import scan


def ids(findings):
    return {f.rule_id for f in findings}


def by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# -- end-to-end on the example repos ---------------------------------------------------

def test_vulnerable_example_triggers_every_rule(examples_dir):
    report = scan(str(examples_dir / "vulnerable-repo"))
    expected = {
        "SEC001", "SEC002", "SEC003", "SEC007", "SEC009", "SEC010", "SEC011",
        "MIS001", "MIS003", "MIS004", "MIS005", "MIS006", "MIS007", "MIS008", "MIS009",
        "VER001", "VER002", "VER003", "VER004", "VER005", "VER006", "VER007", "WF001",
    }
    assert expected <= ids(report.findings)
    assert report.summary["CRITICAL"] >= 5
    assert report.has_findings_at_or_above("HIGH")
    assert not report.errors


def test_clean_example_has_no_findings(examples_dir):
    report = scan(str(examples_dir / "clean-repo"))
    assert report.findings == []
    assert not report.has_findings_at_or_above("INFO")


def test_json_roundtrip(examples_dir):
    report = scan(str(examples_dir / "vulnerable-repo"))
    data = json.loads(to_json(report))
    assert data["summary"]["total"] == len(report.findings)
    restored = Report.from_dict(data)
    assert ids(restored.findings) == ids(report.findings)
    # findings in JSON are sorted most severe first
    severities = [f["severity"] for f in data["findings"]]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert severities == sorted(severities, key=order.index)


def test_text_report_mentions_each_finding(examples_dir):
    report = scan(str(examples_dir / "vulnerable-repo"))
    text = render_text(report)
    for finding in report.findings:
        assert finding.rule_id in text
    assert "Summary:" in text


# -- secrets -------------------------------------------------------------------------------

def test_secret_patterns_are_masked_in_evidence(run_rules):
    findings = run_rules("env:\n  KEY: AKIAIOSFODNN7EXAMPLE\n")
    aws = by_id(findings, "SEC001")
    assert len(aws) == 1 and aws[0].line == 2
    assert "AKIAIOSFODNN7EXAMPLE" not in aws[0].evidence
    assert aws[0].evidence.startswith("AKIA")


def test_secret_reference_and_placeholders_are_not_flagged(run_rules):
    text = (
        "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: ./deploy\n        env:\n"
        "          API_TOKEN: ${{ secrets.API_TOKEN }}\n"
        "          DB_PASSWORD: $DB_PASSWORD\n"
        "          TOKEN_FILE: /run/secrets/token\n"
        "          SECRET_NAME: my-secret\n"
        "          PASSWORD: <redacted>\n"
        "          USE_TOKEN: true\n"
    )
    assert "SEC010" not in ids(run_rules(text))


def test_literal_credential_in_with_and_env_is_flagged(run_rules):
    text = (
        "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: some/action@abcdefabcdefabcdefabcdefabcdefabcdefabcd\n"
        "        with:\n          api-key: 0123456789abcdef\n"
        "      - run: ./x\n        env:\n          DB_PASSWORD: hunter2hunter2\n"
    )
    found = by_id(run_rules(text), "SEC010")
    assert {f.evidence.split(":")[0] for f in found} == {"api-key", "DB_PASSWORD"}


def test_url_with_embedded_credentials(run_rules):
    findings = run_rules("run: git clone https://bob:s3cretpass@example.com/repo.git\n")
    assert by_id(findings, "SEC009")
    assert "s3cretpass" not in by_id(findings, "SEC009")[0].evidence
    # expression-based password is fine
    findings = run_rules("run: git clone https://bob:${{secrets.T}}@example.com/repo.git\n")
    assert not by_id(findings, "SEC009")


def test_echoing_a_secret_is_flagged(run_rules):
    text = (
        "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n          echo start\n          echo ${{ secrets.TOKEN }} | base64\n"
    )
    found = by_id(run_rules(text), "SEC011")
    assert len(found) == 1 and found[0].line == 9


def test_mask():
    assert mask("short") == "*****"
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"


# -- misconfig -----------------------------------------------------------------------------

PWN_REQUEST = (
    "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n        with:\n"
    "          ref: ${{ github.event.pull_request.head.sha }}\n"
)


def test_pull_request_target_with_head_checkout_is_critical(run_rules):
    findings = run_rules(PWN_REQUEST)
    found = by_id(findings, "MIS001")
    assert len(found) == 1 and found[0].severity == "CRITICAL" and found[0].line == 8
    assert "MIS002" not in ids(findings)  # superseded by the specific finding


def test_pull_request_target_alone_is_medium(run_rules):
    findings = run_rules("on: pull_request_target\npermissions: {contents: read}\njobs:\n  a:\n"
                         "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
    assert ids(findings) == {"MIS002"}


def test_workflow_run_head_checkout_is_critical(run_rules):
    text = PWN_REQUEST.replace("pull_request_target", "workflow_run").replace(
        "github.event.pull_request.head.sha", "github.event.workflow_run.head_sha")
    assert by_id(run_rules(text), "MIS001")


def test_plain_pull_request_checkout_is_fine(run_rules):
    findings = run_rules(PWN_REQUEST.replace("pull_request_target", "pull_request"))
    assert "MIS001" not in ids(findings) and "MIS002" not in ids(findings)


@pytest.mark.parametrize("expr", [
    "github.event.issue.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.head_ref",
    "github.event.head_commit.message",
    "github.event.commits[0].message",
    "github.event.pages.*.page_name",
])
def test_expression_injection_contexts(run_rules, expr):
    text = ("on: issues\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo \"${{ " + expr + " }}\"\n")
    found = by_id(run_rules(text), "MIS005")
    assert len(found) == 1 and found[0].severity == "HIGH" and found[0].line == 7


def test_injection_is_critical_under_privileged_trigger(run_rules):
    text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo \"${{ github.event.comment.body }}\"\n")
    assert by_id(run_rules(text), "MIS005")[0].severity == "CRITICAL"


def test_safe_contexts_are_not_flagged(run_rules):
    text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo \"${{ github.sha }} ${{ github.repository }} ${{ matrix.os }}\"\n"
            "        env:\n          TITLE: ${{ github.event.pull_request.title }}\n")
    assert "MIS005" not in ids(run_rules(text))


def test_github_script_injection(run_rules):
    text = ("on: issues\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/github-script@v8\n        with:\n"
            "          script: console.log(\"${{ github.event.issue.title }}\")\n")
    assert by_id(run_rules(text), "MIS005")[0].line == 9


def test_permissions_rules(run_rules):
    base = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
    assert "MIS003" in ids(run_rules(base))
    assert "MIS003" not in ids(run_rules("permissions: {contents: read}\n" + base))
    assert "MIS003" not in ids(run_rules(base.replace("    runs-on:", "    permissions: {}\n    runs-on:")))
    findings = run_rules("permissions: write-all\n" + base)
    assert by_id(findings, "MIS004")[0].line == 1
    assert "MIS003" not in ids(findings)


def test_unsecure_commands_env(run_rules):
    text = ("on: push\npermissions: {contents: read}\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'\n"
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
    found = by_id(run_rules(text), "MIS006")
    assert len(found) == 1 and found[0].line == 4


def test_curl_pipe_shell(run_rules):
    text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n          curl -fsSL https://x.io/i.sh | sudo bash\n          wget -O- https://y | sh\n"
            "          curl -o file.sh https://z && sha256sum -c sums\n")
    assert len(by_id(run_rules(text), "MIS007")) == 2


def test_self_hosted_runner_only_flagged_with_pr_trigger(run_rules):
    job = "permissions: {contents: read}\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: echo\n"
    assert "MIS008" in ids(run_rules("on: pull_request\n" + job))
    assert "MIS008" not in ids(run_rules("on: push\n" + job))


# -- versions ------------------------------------------------------------------------------

def test_parse_version_and_ranges():
    assert parse_version("v4") == (4, float("inf"), float("inf"))
    assert parse_version("4.1.2") == (4, 1, 2)
    assert parse_version("v2.3.4-beta.1") == (2, 3, 4)
    assert parse_version("main") is None
    assert version_in_range(parse_version("v45"), "<46.0.1")
    assert not version_in_range(parse_version("v46"), "<46.0.1")  # floating v46 tracks fixed releases
    assert version_in_range(parse_version("v4.1.2"), ">=4.0.0,<4.1.7")
    assert not version_in_range(parse_version("v4"), ">=4.0.0,<4.1.7")
    assert not version_in_range(parse_version("v4.1.7"), ">=4.0.0,<4.1.7")


def test_parse_docker_ref():
    assert parse_docker_ref("docker://alpine") == ("alpine", None, None)
    assert parse_docker_ref("docker://alpine:3.19") == ("alpine", "3.19", None)
    assert parse_docker_ref("registry:5000/img") == ("registry:5000/img", None, None)
    assert parse_docker_ref("ghcr.io/o/i:1.0@sha256:abc") == ("ghcr.io/o/i", "1.0", "sha256:abc")


def step(uses):
    return ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: " + uses + "\n")


def test_branch_ref_is_high_and_release_branch_is_low(run_rules):
    assert by_id(run_rules(step("actions/checkout@main")), "VER001")[0].severity == "HIGH"
    assert by_id(run_rules(step("pypa/gh-action-pypi-publish@release/v1")), "VER001")[0].severity == "LOW"


def test_tag_ref_is_low_and_sha_is_silent(run_rules):
    assert ids(run_rules(step("actions/checkout@v7"))) == {"VER002"}
    assert ids(run_rules(step("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"))) == set()


def test_sha_with_old_version_comment_is_checked(run_rules):
    findings = run_rules(step("actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e2 # v3.5.0"))
    assert ids(findings) == {"VER003"}


def test_outdated_deprecated_and_vulnerable(run_rules):
    assert "VER004" in ids(run_rules(step("actions/github-script@v7")))
    assert "VER006" in ids(run_rules(step("actions/create-release@v1")))
    vuln = by_id(run_rules(step("tj-actions/changed-files@v45")), "VER005")
    assert vuln and vuln[0].severity == "CRITICAL" and "CVE-2025-30066" in vuln[0].title
    assert "VER005" not in ids(run_rules(step("tj-actions/changed-files@v46")))


def test_reusable_workflow_and_local_refs(run_rules):
    text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n"
            "    uses: org/repo/.github/workflows/x.yml@master\n  b:\n    uses: ./.github/workflows/y.yml\n")
    found = by_id(run_rules(text), "VER001")
    assert len(found) == 1 and "org/repo/.github/workflows/x.yml@" in found[0].remediation


def test_check_latest_uses_live_data(run_rules, monkeypatch):
    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    calls = []

    def fake_get(path, token=None, **kwargs):
        calls.append(path)
        return FakeResponse({"tag_name": "v9.0.0"})

    monkeypatch.setattr("cicd_scanner.rules.versions.github_get", fake_get)
    findings = run_rules(step("actions/checkout@v7"), check_latest=True)
    outdated = by_id(findings, "VER004")
    assert outdated and "v9" in outdated[0].message and "GitHub releases" in outdated[0].message
    assert calls == ["/repos/actions/checkout/releases/latest"]
