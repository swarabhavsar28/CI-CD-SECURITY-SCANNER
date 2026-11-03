from pathlib import Path

import pytest

from cicd_scanner.loader import WorkflowFile
from cicd_scanner.rules import ScanOptions
from cicd_scanner.scanner import scan_files
from cicd_scanner.workflow import Workflow

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture
def run_rules():
    """Run every rule over an inline workflow and return the findings."""

    def _run(yaml_text: str, path: str = ".github/workflows/test.yml", **options):
        report = scan_files("inline", [WorkflowFile(path, yaml_text)], ScanOptions(**options))
        return report.findings

    return _run


@pytest.fixture
def make_workflow():
    return lambda text: Workflow(".github/workflows/test.yml", text)
