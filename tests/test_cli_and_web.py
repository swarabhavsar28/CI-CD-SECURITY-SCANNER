import json
from pathlib import Path

import pytest

from cicd_scanner.cli import main


def test_cli_text_output_and_exit_code(examples_dir, capsys):
    code = main(["scan", str(examples_dir / "vulnerable-repo"), "--no-color"])
    out = capsys.readouterr().out
    assert code == 1
    assert "== CRITICAL ==" in out and "MIS001" in out


def test_cli_fail_on_threshold(examples_dir, capsys):
    assert main(["scan", str(examples_dir / "vulnerable-repo"), "--fail-on", "none"]) == 0
    assert main(["scan", str(examples_dir / "clean-repo")]) == 0
    capsys.readouterr()


def test_cli_json_output_and_file(examples_dir, tmp_path: Path, capsys):
    out_file = tmp_path / "nested" / "report.json"
    code = main(["scan", str(examples_dir / "clean-repo"), "--format", "json", "-o", str(out_file)])
    assert code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["summary"]["total"] == 0
    assert json.loads(out_file.read_text())["files"] == [".github/workflows/ci.yml"]


def test_cli_bad_target(capsys):
    assert main(["scan", "this-is-not-a-target"]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.fixture
def client(examples_dir, tmp_path: Path):
    flask = pytest.importorskip("flask")  # noqa: F841 - web UI is optional
    from cicd_scanner.web.app import create_app

    app = create_app(tmp_path)
    app.config["TESTING"] = True
    main(["scan", str(examples_dir / "vulnerable-repo"), "-o", str(tmp_path / "vuln.json"), "--fail-on", "none",
          "--format", "json"])
    return app.test_client()


def test_web_index_lists_reports(client):
    body = client.get("/").get_data(as_text=True)
    assert "vuln.json" in body and "vulnerable-repo" in body


def test_web_report_page_and_json(client):
    body = client.get("/report/vuln.json").get_data(as_text=True)
    assert "MIS001" in body and 'class="finding CRITICAL"' in body
    response = client.get("/report/vuln.json/json")
    assert response.status_code == 200 and response.json["summary"]["total"] > 0


def test_web_rejects_bad_report_names(client):
    assert client.get("/report/missing.json").status_code == 404
    assert client.get("/report/..%2Fetc%2Fpasswd").status_code == 404


def test_web_scan_form_creates_report(client, examples_dir):
    response = client.post("/scan", data={"target": str(examples_dir / "clean-repo")})
    assert response.status_code == 302 and "/report/" in response.headers["Location"]
    followed = client.get(response.headers["Location"]).get_data(as_text=True)
    assert "No findings" in followed


def test_web_scan_form_bad_target_flashes_error(client):
    body = client.post("/scan", data={"target": "nope-not-here"}, follow_redirects=True).get_data(as_text=True)
    assert "neither an existing path" in body
