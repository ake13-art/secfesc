"""Shared types for secfesc tools."""

from __future__ import annotations

from typing import List

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict


class CheckRegistration(TypedDict):
    name: str
    category: str
    risk: str
    run: object


class CheckResult(TypedDict):
    name: str
    category: str
    risk: str
    status: str
    value: str


class PortEntry(TypedDict):
    port: str
    name: str
    proto: str
    risk: str


class CategoryAccumulator(TypedDict):
    earned: int
    total: int


class FixItem(TypedDict):
    name: str
    key: str
    cmds: List[List[str]]
    risky: bool
    selected: bool
    services: List[str]
