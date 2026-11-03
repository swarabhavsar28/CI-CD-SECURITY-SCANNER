"""YAML loading that keeps source line numbers so findings can point at a line.

PyYAML is a YAML 1.1 parser, which turns the bare ``on:`` key every workflow has
into the boolean ``True``. GitHub's own parser treats it as a string, so the
boolean resolver is narrowed to ``true``/``false`` only.
"""

from __future__ import annotations

import re
from typing import Any

import yaml


class LineDict(dict):
    """dict that remembers the line it starts on and the line of each key."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.line: int = 0
        self.key_lines: dict[Any, int] = {}

    def line_of(self, key: Any) -> int:
        return self.key_lines.get(key, self.line)


class LineList(list):
    def __init__(self, *args):
        super().__init__(*args)
        self.line: int = 0


class WorkflowLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: WorkflowLoader, node: yaml.MappingNode, deep: bool = False) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict()
    mapping.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            key = str(key)
        mapping[key] = loader.construct_object(value_node, deep=True)
        mapping.key_lines[key] = key_node.start_mark.line + 1
    return mapping


def _construct_sequence(loader: WorkflowLoader, node: yaml.SequenceNode, deep: bool = False) -> LineList:
    seq = LineList(loader.construct_object(child, deep=True) for child in node.value)
    seq.line = node.start_mark.line + 1
    return seq


WorkflowLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
WorkflowLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)

_BOOL_TAG = "tag:yaml.org,2002:bool"
WorkflowLoader.yaml_implicit_resolvers = {
    first_char: [(tag, regexp) for tag, regexp in resolvers if tag != _BOOL_TAG]
    for first_char, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    _BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def parse_workflow(text: str) -> tuple[Any, str | None]:
    """Parse workflow YAML. Returns (data, error_message)."""
    try:
        return yaml.load(text, Loader=WorkflowLoader), None
    except yaml.YAMLError as exc:
        return None, str(exc).strip()
