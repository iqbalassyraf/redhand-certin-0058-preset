"""A snapshot of the package's public API, so a breaking change cannot slip in unannounced.

``docs/public_api.json`` records every name in ``redhand_fintech_shield.__all__`` with its kind and
signature (for models, their field names; for classes and protocols, their public methods). A test
compares the live package with it; a deliberate change is made by regenerating the file with
``redhand-shield api --out docs/public_api.json`` and recording it in ``CHANGELOG.md`` under
Added, Changed, Deprecated or Removed (see CONTRIBUTING.md).
"""

from __future__ import annotations

import inspect
import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

_PREFIX = "redhand_fintech_shield"


def _default(value: Any) -> str:
    if value is inspect.Parameter.empty:
        return ""
    if callable(value) and not isinstance(value, type) and hasattr(value, "__qualname__"):
        return f"<{value.__module__}.{value.__qualname__}>"  # no memory addresses
    return repr(value)


def _signature(obj: Any) -> str:
    try:
        parameters = inspect.signature(obj).parameters.values()
    except (TypeError, ValueError):
        return "(unavailable)"
    parts = []
    for p in parameters:
        annotation = p.annotation
        shown = (
            ""
            if annotation is inspect.Parameter.empty
            else annotation
            if isinstance(annotation, str)
            else getattr(annotation, "__name__", str(annotation))
        )
        star = "*" if p.kind is p.VAR_POSITIONAL else "**" if p.kind is p.VAR_KEYWORD else ""
        mark = "|kw" if p.kind is p.KEYWORD_ONLY else ""
        default = _default(p.default)
        parts.append(f"{star}{p.name}:{shown}" + (f"={default}" if default else "") + mark)
    return "(" + ", ".join(parts) + ")"


def _public_methods(cls: type) -> dict[str, str]:
    methods: dict[str, str] = {}
    for klass in reversed(cls.__mro__):
        if not klass.__module__.startswith(_PREFIX):
            continue
        for name, member in vars(klass).items():
            if name.startswith("_"):
                continue
            target = member.fget if isinstance(member, property) else member
            if isinstance(member, staticmethod | classmethod):
                target = member.__func__
            if isinstance(member, property):
                methods[name] = "property"
            elif callable(target):
                methods[name] = _signature(target)
    return dict(sorted(methods.items()))


def describe(obj: Any) -> dict[str, Any]:
    """The part of ``obj`` that callers depend on."""
    if isinstance(obj, type):
        if issubclass(obj, BaseException):
            return {"kind": "exception", "init": _signature(obj)}
        if issubclass(obj, BaseModel):
            fields = {n: {"required": f.is_required()} for n, f in sorted(obj.model_fields.items())}
            return {"kind": "model", "fields": fields}
        if issubclass(obj, Enum):
            return {"kind": "enum", "members": {m.name: m.value for m in obj}}
        kind = "protocol" if getattr(obj, "_is_protocol", False) else "class"
        entry: dict[str, Any] = {"kind": kind, "methods": _public_methods(obj)}
        if kind == "class":
            entry["init"] = _signature(obj)
        return entry
    if callable(obj):
        return {"kind": "function", "signature": _signature(obj)}
    return {"kind": "constant", "type": type(obj).__name__}


def snapshot() -> dict[str, Any]:
    """Describe every name in the package's ``__all__``."""
    import redhand_fintech_shield as package

    return {name: describe(getattr(package, name)) for name in sorted(package.__all__)}


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def diff(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Human-readable differences between two snapshots (empty if identical)."""
    changes = [f"removed: {name}" for name in sorted(set(old) - set(new))]
    changes += [f"added: {name}" for name in sorted(set(new) - set(old))]
    changes += [f"changed: {n}" for n in sorted(set(old) & set(new)) if old[n] != new[n]]
    return changes


def default_snapshot_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "public_api.json"
