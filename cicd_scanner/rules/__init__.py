"""Rule registry. Each rule module exposes ``check(workflow, options) -> list[Finding]``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..models import Finding
from ..workflow import Workflow
from . import misconfig, secrets, versions


@dataclass
class ScanOptions:
    check_latest: bool = False
    token: str | None = None
    cache: dict[str, Any] = field(default_factory=dict)  # shared scratch space across files
    warnings: set[str] = field(default_factory=set)  # non-fatal problems, surfaced in the report


RuleFn = Callable[[Workflow, ScanOptions], list[Finding]]

RULES: list[RuleFn] = [secrets.check, misconfig.check, versions.check]

__all__ = ["RULES", "ScanOptions", "RuleFn"]
