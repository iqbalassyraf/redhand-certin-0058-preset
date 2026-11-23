"""A stable fingerprint of the rules a policy puts in force.

The fingerprint is stamped on every audit record and finding, so a decision can be traced to the
exact policy that made it. It covers every limit and rule and leaves out what does not change a
decision: provenance, and the deployment settings (paths, ids) that ``layers.DIRECTIONS``
classifies as ``free``. Spelling differences that mean the same thing (``10000.00`` against
``10000``, key order, set order) do not change it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import PolicyConfig


def _canon(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, bool | int | float | str) or value is None:
        return value
    if isinstance(value, Enum):
        return _canon(value.value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _canon(v) for k, v in value.items()}
    if isinstance(value, set | frozenset):
        return sorted((_canon(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(value, list | tuple):
        return [_canon(v) for v in value]
    return str(value)


def fingerprint_document(policy: PolicyConfig) -> dict[str, Any]:
    """The canonical document that is hashed (useful when explaining a fingerprint change)."""
    from .layers import DIRECTIONS, SECTIONS  # lazy: layers imports models

    dump = policy.model_dump()
    document: dict[str, Any] = {}
    for field, value in dump.items():
        if field == "provenance" or DIRECTIONS.get(field) == "free":
            continue
        if field == "token_keys":  # which keys are trusted matters; where their files live does not
            value = [{"kid": k["kid"], "retire_at": k["retire_at"]} for k in value]
        if field in SECTIONS:
            value = {k: v for k, v in value.items() if DIRECTIONS.get(f"{field}.{k}") != "free"}
        document[field] = _canon(value)
    return document


def policy_fingerprint(policy: PolicyConfig) -> str:
    """SHA-256 (hex) of the canonical rules-in-force document."""
    blob = json.dumps(
        fingerprint_document(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
