"""Global registry of available offensive tools.

Wrappers register themselves at import time via the `@register` decorator.
The agent calls `all_tools()` to learn what's available, and `get(name)` to
fetch a specific one.
"""
from __future__ import annotations

from typing import TypeVar

from tools.base import OffensiveTool

_REGISTRY: dict[str, type[OffensiveTool]] = {}

T = TypeVar("T", bound=OffensiveTool)


def register(cls: type[T]) -> type[T]:
    """Class decorator — adds the wrapper to the registry under `cls.name`."""
    if not getattr(cls, "name", None):
        raise ValueError(f"{cls.__name__} is missing a `name` class attribute")
    if cls.name in _REGISTRY:
        raise ValueError(f"Tool '{cls.name}' is already registered")
    _REGISTRY[cls.name] = cls
    return cls


def get(name: str) -> OffensiveTool:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown tool: {name!r}. Available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]()


def all_tools() -> list[dict[str, object]]:
    """Compact catalogue for the agent prompt."""
    return [
        {
            "name": cls.name,
            "phase": cls.phase,
            "mitre_techniques": cls.mitre_techniques,
            "description": cls.description.strip(),
        }
        for cls in _REGISTRY.values()
    ]


def names() -> list[str]:
    return sorted(_REGISTRY)
