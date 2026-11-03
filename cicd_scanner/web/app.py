"""Flask app: list saved JSON reports, view one, or run a new scan from the browser.

Intended for local use (binds to 127.0.0.1 by default). It scans whatever target is
typed into the form, including local paths, so do not expose it publicly.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for

from ..loader import TargetError
from ..models import CATEGORIES, SEVERITIES, Report
from ..report import to_json
from ..scanner import scan

REPORT_NAME_RE = re.compile(r"^[\w.-]+\.json$")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()[:60] or "scan"


def create_app(reports_dir: str | os.PathLike[str] = "reports") -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("CICD_SCANNER_SECRET", os.urandom(16).hex())
    reports_path = Path(reports_dir).resolve()
    reports_path.mkdir(parents=True, exist_ok=True)
    app.config["REPORTS_DIR"] = reports_path

    def report_file(name: str) -> Path:
        if not REPORT_NAME_RE.match(name):
            abort(404)
        path = (reports_path / name).resolve()
        if path.parent != reports_path or not path.is_file():
            abort(404)
        return path

    def load_report(path: Path) -> Report:
        return Report.from_dict(json.loads(path.read_text(encoding="utf-8")))

    @app.get("/")
    def index():
        entries = []
        for path in sorted(reports_path.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                report = load_report(path)
            except (ValueError, TypeError):
                continue
            entries.append({"name": path.name, "report": report, "summary": report.summary})
        return render_template("index.html", entries=entries, severities=SEVERITIES)

    @app.post("/scan")
    def run_scan():
        target = request.form.get("target", "").strip()
        if not target:
            flash("Enter a repository URL or local path.", "error")
            return redirect(url_for("index"))
        try:
            report = scan(
                target,
                token=request.form.get("token") or None,
                check_latest=bool(request.form.get("check_latest")),
            )
        except TargetError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        name = f"{stamp}-{_slug(target)}.json"
        (reports_path / name).write_text(to_json(report), encoding="utf-8")
        return redirect(url_for("view_report", name=name))

    @app.get("/report/<name>")
    def view_report(name: str):
        path = report_file(name)
        report = load_report(path)
        return render_template(
            "report.html",
            name=name,
            report=report,
            findings=report.sorted_findings(),
            summary=report.summary,
            severities=SEVERITIES,
            categories=CATEGORIES,
        )

    @app.get("/report/<name>/json")
    def report_json(name: str):
        return send_file(report_file(name), mimetype="application/json", download_name=name)

    @app.post("/report/<name>/delete")
    def delete_report(name: str):
        report_file(name).unlink()
        flash(f"Deleted {name}.", "info")
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
