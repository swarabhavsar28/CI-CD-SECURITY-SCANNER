<p align="center">
  <img src="docs/logo.svg" alt="cicd-scanner logo" width="96">
</p>

<h1 align="center">cicd-scanner</h1>

<p align="center">
  <strong>Static security scanner for GitHub Actions workflows.</strong><br>
  Catch leaked secrets, dangerous triggers and compromised actions before they reach <code>main</code>.
</p>

<p align="center">
  <a href="https://github.com/swarabhavsar/cicd-scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/swarabhavsar/cicd-scanner/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Tests" src="https://img.shields.io/badge/tests-64%20passing-brightgreen">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-blueviolet">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-detects">What it detects</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#web-ui">Web UI</a> ·
  <a href="#ci-integration">CI integration</a> ·
  <a href="#rule-reference">Rules</a> ·
  <a href="#contributing">Contributing</a>
</p>

![cicd-scan scanning github.com/ADNAN-ZEYA/SafeChat: 11 HIGH, 1 MEDIUM, 6 LOW findings, exit code 1](docs/screenshots/cli.png)

*Real output from `cicd-scan scan https://github.com/ADNAN-ZEYA/SafeChat` — a live, public
repository. Verify it yourself: [SafeChat's workflow file](https://github.com/ADNAN-ZEYA/SafeChat/blob/main/.github/workflows/ci-cd.yml).*

---

## Overview

GitHub Actions workflows are code that runs with your repository's secrets and a
write-capable token. A single `pull_request_target` mistake, an injected
`${{ github.event.issue.title }}`, or an action tag that a maintainer's compromised
account moved can hand that access to anyone who opens a pull request.

**cicd-scanner** reads every file in `.github/workflows/`, either from a local checkout or
straight from GitHub through the REST API, and reports what it finds with a rule ID,
severity, exact file and line, masked evidence and a concrete fix. Output is JSON for
machines, a coloured summary for terminals, and a small web UI for browsing reports.

| At a glance | |
| --- | --- |
| **Input** | GitHub repository URL, `owner/repo`, or any local path |
| **Output** | JSON report · terminal summary · web UI |
| **Checks** | 23 rules across secrets, misconfiguration and action versions |
| **Runtime** | Python 3.10+, two dependencies (PyYAML, requests); Flask only for the UI |
| **CI-ready** | Non-zero exit code above a severity threshold you choose |

## What it detects

<table>
<tr>
<th align="left" width="33%">🔑 Exposed secrets</th>
<th align="left" width="33%">⚠️ Misconfigurations</th>
<th align="left" width="33%">📦 Action versions</th>
</tr>
<tr valign="top">
<td>
<ul>
<li>AWS, GitHub, npm, Slack, Stripe and Google tokens</li>
<li>Private key blocks and JWTs</li>
<li><code>https://user:password@host</code> URLs</li>
<li>Credential-named <code>env:</code> / <code>with:</code> values set to literals instead of <code>${{ secrets.* }}</code></li>
<li>Secrets echoed to the job log</li>
</ul>
</td>
<td>
<ul>
<li><strong>Pwn requests</strong>: <code>pull_request_target</code> / <code>workflow_run</code> workflows that check out the PR head</li>
<li><strong>Expression injection</strong> of untrusted event data into <code>run:</code> or <code>github-script</code></li>
<li>Missing <code>permissions:</code> or <code>write-all</code></li>
<li><code>ACTIONS_ALLOW_UNSECURE_COMMANDS</code></li>
<li><code>curl | bash</code>, self-hosted runners on PR triggers, <code>secrets: inherit</code></li>
</ul>
</td>
<td>
<ul>
<li>Actions pinned to a branch or a mutable tag instead of a commit SHA</li>
<li>Retired majors (Node 12/16, shut-down artifact/cache versions)</li>
<li>Newer major available</li>
<li><strong>Known-compromised versions</strong>: <code>tj-actions/changed-files</code> (CVE-2025-30066), <code>reviewdog/action-setup</code> (CVE-2025-30154), <code>actions/download-artifact</code> (CVE-2024-42471)</li>
<li>Archived actions, untagged container images</li>
</ul>
</td>
</tr>
</table>

See the full [rule reference](#rule-reference) for IDs and severities.

## Screenshots

Every screenshot below is a genuine run against a real, public repository
([ADNAN-ZEYA/SafeChat](https://github.com/ADNAN-ZEYA/SafeChat)) — the app running on
`127.0.0.1:5000`, not mockups. Open the repo yourself and compare against the findings.

**CLI** — the hero image above. `cicd-scan scan https://github.com/ADNAN-ZEYA/SafeChat`
fetches the workflow over the GitHub API (no clone), finds 18 real issues — mostly
retired action majors and third-party actions pinned to `@master` instead of a SHA — and
exits `1` because HIGH findings are at or above the default `--fail-on high` threshold.

**Web UI — dashboard** (`cicd-scan serve`) lists every saved report with severity badges.
The SafeChat scan sits alongside the bundled examples used in [Quick start](#quick-start).

![Web UI dashboard: SafeChat report (11 HIGH · 1 MEDIUM · 6 LOW) plus the bundled examples](docs/screenshots/web-index.png)

**Web UI — report detail** for the SafeChat scan: severity counters, then one card per
finding with the rule ID, exact file:line, an explanation, masked evidence and a fix —
here, `actions/checkout@v3` on a retired Node runtime and `aquasecurity/trivy-action@master`
pinned to a mutable branch.

![Web UI report detail for SafeChat listing real HIGH findings with evidence and fixes](docs/screenshots/web-report.png)

**Web UI — filtering**, narrowed to HIGH findings in the versions category
(`?severity=HIGH&category=versions`, 11 of 18 shown). Filters live in the URL, so a
filtered view can be bookmarked or sent to a teammate.

![Web UI report filtered to HIGH severity, versions category: 11 of 18 findings shown](docs/screenshots/web-report-filtered.png)

## Quick start

### Option A - one command

Clone the repository, then run the launcher for your platform. It creates a virtual
environment, installs dependencies, scans the bundled vulnerable example and opens the
web UI at <http://127.0.0.1:5000>.

```bash
git clone https://github.com/swarabhavsar/cicd-scanner.git
cd cicd-scanner
```

| Windows | macOS / Linux |
| --- | --- |
| `run.bat` | `./run.sh` |

### Option B - manual

```bash
git clone https://github.com/swarabhavsar/cicd-scanner.git
cd cicd-scanner
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

Scan the bundled example that trips every rule:

```bash
python -m cicd_scanner scan examples/vulnerable-repo
```

Scan any public repository on GitHub (no `git` needed - files are fetched via the API):

```bash
python -m cicd_scanner scan https://github.com/owner/repo
```

### Option C - install as a CLI

```bash
pip install -e ".[web]"
cicd-scan scan owner/repo
```

## Usage

```text
cicd-scan scan  TARGET [-o FILE] [--format text|json] [--fail-on SEVERITY]
                       [--token TOKEN] [--check-latest] [--no-color]
cicd-scan serve [--reports-dir DIR] [--host HOST] [--port PORT]
```

### Targets

| Form | Example |
| --- | --- |
| Repository URL | `https://github.com/owner/repo` · `https://github.com/owner/repo/tree/branch` · `git@github.com:owner/repo.git` |
| Shorthand | `owner/repo` · `owner/repo@ref` |
| Local repository | `.` · `C:\projects\my-repo` |
| Workflows directory or single file | `my-repo/.github/workflows` · `my-repo/.github/workflows/ci.yml` |

### Options

| Option | Description |
| --- | --- |
| `-o, --output FILE` | Also write the JSON report to `FILE` (parent directories are created). |
| `--format text\|json` | What to print to stdout. Default `text`. |
| `--fail-on SEVERITY` | Exit `1` if any finding is at or above `critical`, `high`, `medium`, `low` or `info`; `none` always exits `0`. Default `high`. |
| `--token TOKEN` | GitHub token for private repositories and higher API rate limits. Falls back to `$GITHUB_TOKEN` / `$GH_TOKEN`. |
| `--check-latest` | Query GitHub for each action's latest release instead of the bundled snapshot (one request per distinct action; falls back to the snapshot with a warning if the API is unavailable). |
| `--no-color` | Plain output. `NO_COLOR` is honoured too. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | Findings at or above the threshold |
| `2` | Target could not be loaded (bad path, repository not found, network error) |

### Examples

```bash
# Text summary on screen, JSON to a file, fail on MEDIUM or worse
cicd-scan scan . -o reports/scan.json --fail-on medium

# JSON only - pipe to jq, upload as an artifact, feed a dashboard
cicd-scan scan owner/repo --format json > report.json

# Private repository with live version lookups
cicd-scan scan owner/private-repo --token ghp_xxx --check-latest
```

## Web UI

```bash
python -m cicd_scanner serve --reports-dir reports
```

The index lists every JSON report in the directory (anything saved with `-o` appears
automatically), a form runs new scans, and each report can be filtered by severity and
category or downloaded as JSON. Filters are reflected in the URL
(`/report/<name>?severity=CRITICAL,HIGH&category=misconfig`) so a view can be bookmarked or
shared. The server binds to localhost only.

See the [Screenshots](#screenshots) section above for the dashboard, report detail and filtering in action.

## CI integration

Run the scanner on every pull request so changes that weaken the pipeline fail the build:

```yaml
name: workflow-audit
on: [pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
      - run: pip install "cicd-scanner @ git+https://github.com/swarabhavsar/cicd-scanner"
      - run: cicd-scan scan . --fail-on high -o cicd-scan-report.json
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        if: always()
        with:
          name: cicd-scan-report
          path: cicd-scan-report.json
```

This repository dogfoods the tool: [`ci.yml`](.github/workflows/ci.yml) scans its own
workflows with `--fail-on low`, so the build fails on anything short of SHA-pinned,
least-privilege configuration.

## Report format

```json
{
  "tool": { "name": "cicd-scanner", "version": "0.1.0" },
  "target": "https://github.com/owner/repo",
  "scanned_at": "2026-09-18T22:26:17+00:00",
  "files": [".github/workflows/ci.yml"],
  "summary": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 2, "LOW": 3, "INFO": 0, "total": 6 },
  "findings": [
    {
      "rule_id": "MIS001",
      "title": "Untrusted pull request code checked out in privileged workflow",
      "severity": "CRITICAL",
      "category": "misconfig",
      "file": ".github/workflows/ci.yml",
      "line": 16,
      "message": "Job 'build', step using actions/checkout@v2 checks out the pull request head while ...",
      "evidence": "ref: ${{ github.event.pull_request.head.sha }}",
      "remediation": "Run untrusted code under 'pull_request' instead. ..."
    }
  ],
  "errors": []
}
```

Findings are ordered most severe first. Secret evidence is masked
(`AKIA************MPLE`), so a report never reproduces the credential it found.

## Rule reference

<details>
<summary><strong>Secrets</strong> (SEC)</summary>

| ID | Severity | Detects |
| --- | --- | --- |
| SEC001 | CRITICAL | AWS access key ID |
| SEC002 | CRITICAL | GitHub personal access token (`ghp_`, `gho_`, `github_pat_`, ...) |
| SEC003 | CRITICAL | Slack token |
| SEC004 | CRITICAL | Private key block (RSA, EC, OpenSSH, PGP) |
| SEC005 | HIGH | Google API key |
| SEC006 | CRITICAL | Stripe live secret key |
| SEC007 | CRITICAL | npm access token |
| SEC008 | HIGH | JSON Web Token |
| SEC009 | HIGH | `scheme://user:password@host` URL with a literal password |
| SEC010 | HIGH | Credential-named `env:` / `with:` / `secrets:` key set to a literal value |
| SEC011 | MEDIUM | `echo` / `printf` / `cat` of a `${{ secrets.* }}` value |

</details>

<details>
<summary><strong>Misconfiguration</strong> (MIS)</summary>

| ID | Severity | Detects |
| --- | --- | --- |
| MIS001 | CRITICAL | `pull_request_target`, `workflow_run` or `issue_comment` workflow checks out the PR head (or runs `gh pr checkout`) |
| MIS002 | MEDIUM | `pull_request_target` trigger in use |
| MIS003 | MEDIUM | No `permissions:` block at workflow or job level |
| MIS004 | HIGH | `permissions: write-all` |
| MIS005 | HIGH · CRITICAL under privileged triggers | Untrusted event field (`issue.title`, `pull_request.body`, `head_ref`, commit messages, comment bodies, ...) expanded inside `run:` or `actions/github-script` |
| MIS006 | HIGH | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` |
| MIS007 | MEDIUM | `curl ... \| bash`-style remote script execution |
| MIS008 | MEDIUM | Self-hosted runner in a PR-triggered workflow |
| MIS009 | LOW | `secrets: inherit` passed to a reusable workflow |
| WF001 | LOW | Workflow is not valid YAML (secret patterns still run on the raw text) |

</details>

<details>
<summary><strong>Action versions</strong> (VER)</summary>

| ID | Severity | Detects |
| --- | --- | --- |
| VER001 | HIGH · LOW for documented release branches | Action referenced by a branch (`@main`) |
| VER002 | LOW | Action referenced by a tag instead of a commit SHA |
| VER003 | HIGH | Major version GitHub has retired (Node 12/16 runtime, shut-down artifact/cache services) |
| VER004 | MEDIUM | Newer major version available |
| VER005 | CRITICAL / HIGH | Version inside a known-vulnerable range (CVE-2025-30066, CVE-2025-30154, CVE-2024-42471) |
| VER006 | MEDIUM | Archived or deprecated action (`actions/create-release`, `actions/setup-ruby`, ...) |
| VER007 | MEDIUM | Container image with no tag or `:latest` and no digest |

SHA-pinned actions are versioned through the `# vX.Y.Z` comment convention
(`uses: actions/checkout@<sha> # v7.0.1`). Version data lives in
[`known_actions.json`](cicd_scanner/data/known_actions.json), which records its
`snapshot_date`; `--check-latest` overrides it with live release data.

</details>

## How it works

```text
 target ──▶ loader ──▶ yaml_parser ──▶ rules ──▶ report
            │           │               │          │
   URL or   │  GitHub   │  PyYAML with  │ secrets  │ JSON
   path     │  REST API │  line numbers │ misconfig│ text
            │  or disk  │  ("on:" kept  │ versions │ web UI
            │           │   a string)   │          │
```

```text
cicd_scanner/
├── cli.py                  argparse entry point: scan / serve
├── loader.py               resolves URL or path into workflow files
├── yaml_parser.py          line-number-aware PyYAML loader
├── workflow.py             parsed workflow + shared helpers
├── scanner.py              runs every rule, builds the Report
├── report.py               JSON and text rendering
├── rules/
│   ├── secrets.py          SEC rules
│   ├── misconfig.py        MIS rules
│   └── versions.py         VER rules
├── data/known_actions.json latest / minimum-supported majors, vulnerable ranges
└── web/                    Flask app and templates
examples/
├── vulnerable-repo/        trips every rule - demos and tests
└── clean-repo/             SHA-pinned, least-privilege, zero findings
tests/                      pytest suite (rules, parser, loader, CLI, web)
```

## Development

```bash
pip install -r requirements.txt
python -m pytest
```

**Adding a rule**

1. Write a function in the matching `rules/*.py` module that returns `Finding` objects and
   call it from that module's `check()`.
2. Give the finding a rule ID, severity, category, file, line, message, evidence and
   remediation.
3. Add a case to `examples/vulnerable-repo` and an assertion in `tests/test_rules.py`.

## Roadmap

- SARIF output for GitHub code scanning
- Entropy-based secret detection
- Transitive scanning of composite actions and reusable workflows
- GitLab CI and Azure Pipelines support

## Limitations

- Coverage is intentionally focused. For exhaustive linting also see
  [zizmor](https://github.com/woodruffw/zizmor), [actionlint](https://github.com/rhysd/actionlint)
  and CodeQL's workflow queries.
- Secret detection is pattern-based; unusual token formats are only caught when they sit
  under a credential-looking key.
- Remote scans read a single ref and do not inspect git history.
- The bundled action snapshot ages; use `--check-latest` or update `known_actions.json`.

## Contributing

Issues and pull requests are welcome. Please add or update tests for any rule change and
make sure `python -m pytest` passes before opening a PR.

## License

Released under the [MIT License](LICENSE).
