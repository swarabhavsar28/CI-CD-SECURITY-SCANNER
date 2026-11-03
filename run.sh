#!/usr/bin/env bash
# One-command local setup for macOS/Linux:
#   creates .venv, installs dependencies, runs a demo scan, starts the web UI.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

if [ ! -x ".venv/bin/python" ]; then
    echo "[1/4] Creating virtual environment..."
    "$PY" -m venv .venv
else
    echo "[1/4] Virtual environment already exists."
fi

echo "[2/4] Installing dependencies..."
.venv/bin/python -m pip install -q -r requirements.txt

echo "[3/4] Running demo scan on examples/vulnerable-repo..."
.venv/bin/python -m cicd_scanner scan examples/vulnerable-repo -o reports/vulnerable-example.json --fail-on none
.venv/bin/python -m cicd_scanner scan examples/clean-repo -o reports/clean-example.json --fail-on none > /dev/null

echo
echo "[4/4] Starting web UI at http://127.0.0.1:5000  (press Ctrl+C to stop)"
exec .venv/bin/python -m cicd_scanner serve --reports-dir reports
