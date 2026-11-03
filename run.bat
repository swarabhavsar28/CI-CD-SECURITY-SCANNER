@echo off
rem One-command local setup for Windows:
rem   creates .venv, installs dependencies, runs a demo scan, starts the web UI.
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Creating virtual environment...
    python -m venv .venv || goto :fail
) else (
    echo [1/4] Virtual environment already exists.
)

echo [2/4] Installing dependencies...
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt || goto :fail

echo [3/4] Running demo scan on examples\vulnerable-repo...
".venv\Scripts\python.exe" -m cicd_scanner scan examples\vulnerable-repo -o reports\vulnerable-example.json --fail-on none
".venv\Scripts\python.exe" -m cicd_scanner scan examples\clean-repo -o reports\clean-example.json --fail-on none >nul

echo.
echo [4/4] Starting web UI at http://127.0.0.1:5000  (press Ctrl+C to stop)
".venv\Scripts\python.exe" -m cicd_scanner serve --reports-dir reports
goto :eof

:fail
echo.
echo Setup failed. Make sure Python 3.10+ is installed and on PATH (https://www.python.org/downloads/).
exit /b 1
