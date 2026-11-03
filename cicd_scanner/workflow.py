"""A parsed workflow file plus the helpers the rules share."""

from __future__ import annotations

from typing import Any, Iterator

from .yaml_parser import LineDict, parse_workflow


class Workflow:
    def __init__(self, path: str, content: str):
        self.path = path
        self.content = content
        self.lines = content.splitlines()
        data, error = parse_workflow(content)
        if error is None and not isinstance(data, dict):
            error = "workflow root is not a mapping"
            data = None
        self.data: LineDict | None = data
        self.parse_error = error

    # -- structure -----------------------------------------------------------------

    @property
    def triggers(self) -> set[str]:
        on = self.data.get("on") if self.data else None
        if isinstance(on, str):
            return {on}
        if isinstance(on, list):
            return {str(item) for item in on}
        if isinstance(on, dict):
            return {str(key) for key in on}
        return set()

    def jobs(self) -> Iterator[tuple[str, LineDict]]:
        jobs = self.data.get("jobs") if self.data else None
        if isinstance(jobs, dict):
            for name, job in jobs.items():
                if isinstance(job, dict):
                    yield str(name), job

    @staticmethod
    def steps(job: dict) -> Iterator[LineDict]:
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    yield step

    # -- line lookup ---------------------------------------------------------------

    @staticmethod
    def line_of(obj: Any, key: Any = None) -> int:
        if isinstance(obj, LineDict):
            return obj.line_of(key) if key is not None else obj.line
        return getattr(obj, "line", 0) or 0

    def find_line(self, needle: str, start: int = 1) -> int:
        """First line at/after ``start`` containing ``needle``; falls back to ``start``."""
        for index in range(max(start, 1) - 1, len(self.lines)):
            if needle in self.lines[index]:
                return index + 1
        return start

    def raw_line(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""


def describe_step(step: dict, index: int) -> str:
    if step.get("name"):
        return "step " + repr(step["name"])
    if step.get("id"):
        return "step " + repr(step["id"])
    if step.get("uses"):
        return "step using " + str(step["uses"])
    return "step #" + str(index + 1)
