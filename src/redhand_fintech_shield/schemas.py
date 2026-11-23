"""JSON Schemas for the documents a host application exchanges with the shield.

The committed ``schemas/`` directory is the contract: a host validates against it, and any change
to a model shows up as a diff there (``tests/test_schemas.py`` fails until it is regenerated with
``redhand-shield schema --out schemas``). Each document carries a URN ``$id`` with a version that
is bumped by hand when a change is not backwards compatible.

The finding and mode shapes (RedHand M4.2 / M4.3) were written from the design specification, not
from a RedHand release; they must be diffed against RedHand's own schemas when those are available.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .exceptions import PolicyLoadError
from .manifest import PresetManifest
from .models import (
    ApprovalClaims,
    ApprovalRequest,
    AuditRecord,
    M42Finding,
    PolicyConfig,
    TokenClaims,
    ToolCallContext,
)

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

# name -> (model, document version). Bump the version when a change breaks existing documents.
SCHEMAS: dict[str, tuple[type[BaseModel], int]] = {
    "policy": (PolicyConfig, 1),
    "finding": (M42Finding, 1),
    "audit_record": (AuditRecord, 1),
    "approval_request": (ApprovalRequest, 1),
    "approval_claims": (ApprovalClaims, 1),
    "token_claims": (TokenClaims, 1),
    "tool_call_context": (ToolCallContext, 1),
    "preset_manifest": (PresetManifest, 1),
}
INDEX_NAME = "index.json"


def schema_document(name: str) -> dict[str, Any]:
    """The JSON Schema for one document, with its URN id and dialect."""
    model, version = SCHEMAS[name]
    document = model.model_json_schema()
    document["$schema"] = JSON_SCHEMA_DIALECT
    document["$id"] = f"urn:redhand:shield:{name}:v{version}"
    return document


def render(document: dict[str, Any]) -> str:
    """Canonical text form (stable key order) so a regenerated file is byte-identical."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def all_files() -> dict[str, str]:
    """File name -> content for every schema plus the index that lists them with their hashes."""
    files = {f"{name}.schema.json": render(schema_document(name)) for name in SCHEMAS}
    index = {
        "schemas": [
            {
                "name": name,
                "file": f"{name}.schema.json",
                "id": schema_document(name)["$id"],
                "sha256": hashlib.sha256(files[f"{name}.schema.json"].encode("utf-8")).hexdigest(),
            }
            for name in SCHEMAS
        ]
    }
    files[INDEX_NAME] = render(index)
    return files


def write_schemas(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for file_name, content in all_files().items():
        path = out / file_name
        path.write_text(content, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def check_schemas(directory: Path) -> list[str]:
    """Problems found comparing ``directory`` with the schemas generated from the code."""
    problems: list[str] = []
    expected = all_files()
    for file_name, content in expected.items():
        path = directory / file_name
        if not path.is_file():
            problems.append(f"missing: {file_name}")
        elif path.read_text(encoding="utf-8") != content:
            problems.append(f"out of date: {file_name}")
    if directory.is_dir():
        problems += [
            f"unexpected: {p.name}"
            for p in sorted(directory.glob("*.json"))
            if p.name not in expected
        ]
    return problems


def default_schema_dir() -> Path:
    """The committed schemas (repo checkout first, then an installed wheel's shared data)."""
    candidates = [
        Path(__file__).resolve().parents[2] / "schemas",
        Path(sys.prefix) / "share" / "redhand-certin-0058-preset" / "schemas",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise PolicyLoadError("bundled schemas not found; pass --out DIR")
