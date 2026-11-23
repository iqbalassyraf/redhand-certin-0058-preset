"""Composable policies: a policy file may ``extends`` another and may only tighten it.

An overlay lets an operator adjust the shipped preset without forking it. The loader merges the
overlay onto its parent, validates the result, then compares it with the parent field by field. A
change that makes the policy weaker is refused unless the overlay lists that exact field under
``loosen:``; a field the base lists under ``locked:`` can never be loosened. Every accepted
loosening is recorded in ``PolicyConfig.provenance``.

Fields the direction table does not know are treated as ``fixed`` (must not change), so a field
added to the policy later is safe by default; a test keeps the table complete.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .exceptions import PolicyLoadError
from .models import PolicyConfig, PolicyProvenance

META_KEYS = ("extends", "loosen", "locked")
MAX_DEPTH = 4
_PRESET_ID = re.compile(r"^[A-Za-z0-9_-]+$")
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_INF = float("inf")

# kind -> meaning of "tighter":
#   lower / higher        numeric (None counts as unlimited for lower)
#   true / false          the boolean that is stricter
#   superset / subset     membership of a set
#   scope                 a tool set where empty means "all tools" (the broadest, so tightest)
#   enum:a,b,c            later is tighter
#   map_lower/map_higher  per-key numbers; a new key loosens (an unknown key fails closed today)
#   caps                  like map_lower, but a map may be filled in when it was empty (turns the
#                         scope on) and may not be emptied (turns it off)
#   interval              a (start, end) pair; narrower is tighter
#   bindings              existing tool bindings must stay as they are; new tools are free
#   rules / exemptions    handled specially
#   fixed                 must not change
#   free                  deployment setting (paths, ids); never a limit
DIRECTIONS: dict[str, str] = {
    "preset_id": "free",
    "mode": "enum:observe_only,enforce",
    "issuer": "free",
    "max_token_ttl_seconds": "lower",
    "verifier_public_key_path": "free",
    "micro_tx.ceilings": "map_higher",
    "micro_tx.max_probes": "lower",
    "micro_tx.window_seconds": "higher",
    "velocity.max_calls": "lower",
    "velocity.window_seconds": "higher",
    "velocity.max_total_calls": "lower",
    "hitl.thresholds": "map_lower",
    "hitl.protected_tools": "superset",
    "off_hours.enabled": "true",
    "off_hours.timezone": "fixed",
    "off_hours.business_hours": "interval",
    "off_hours.weekend_days": "superset",
    "off_hours.holidays": "superset",
    "off_hours.tighten_factor": "lower",
    "off_hours.mandatory_hitl": "true",
    "structuring.enabled": "true",
    "structuring.protected_tools": "scope",
    "structuring.thresholds": "map_lower",
    "structuring.window_seconds": "higher",
    "structuring.min_tx_count": "lower",
    "structuring.scopes": "superset",
    "structuring.max_keys": "free",
    "new_beneficiary.enabled": "true",
    "new_beneficiary.thresholds": "map_lower",
    "new_beneficiary.known_beneficiaries": "subset",
    "new_beneficiary.action": "enum:hitl_required,block",
    "sequence.enabled": "true",
    "sequence.recon_tools": "superset",
    "sequence.payment_tools": "superset",
    "sequence.min_recon_calls": "lower",
    "sequence.window_seconds": "higher",
    "tool_bindings.tools": "bindings",
    "tool_bindings.legacy_fallback": "false",
    "tool_bindings.require_for_protected": "true",
    "approval.verifier_public_key_path": "free",
    "approval.issuer": "free",
    "approval.max_ttl_seconds": "lower",
    "approval.nonce_journal_path": "free",
    "approval.max_nonces": "free",
    "approval.allow_legacy_step_up": "false",
    "aggregation.base_currency": "fixed",
    "aggregation.rates": "fixed",
    "cumulative_cap.enabled": "true",
    "cumulative_cap.protected_tools": "scope",
    "cumulative_cap.window_seconds": "higher",
    "cumulative_cap.per_run": "caps",
    "cumulative_cap.per_subject": "caps",
    "cumulative_cap.action": "enum:hitl_required,block",
    "cumulative_cap.max_keys": "free",
    "rules": "rules",
    "exemptions": "exemptions",
    "exemption_max_days": "lower",
    "provenance": "free",
    "quarantine_on_block": "true",
    "audit_path": "free",
    "audit_fsync": "true",
    "quarantine_journal_path": "free",
}


# Policy sections whose fields are classified individually ("section.field" in DIRECTIONS).
_SECTIONS = (
    "micro_tx",
    "velocity",
    "hitl",
    "off_hours",
    "structuring",
    "new_beneficiary",
    "sequence",
    "tool_bindings",
    "approval",
    "aggregation",
    "cumulative_cap",
)


@dataclass(frozen=True, slots=True)
class Loosening:
    path: str
    detail: str


# --------------------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------------------


def _num(value: Any) -> float | Any:
    return _INF if value is None else value


def _compare(kind: str, path: str, old: Any, new: Any) -> list[Loosening]:
    out: list[Loosening] = []
    if kind == "free" or old == new:
        return out
    if kind in ("lower", "higher"):
        weaker = _num(new) > _num(old) if kind == "lower" else _num(new) < _num(old)
        if weaker:
            out.append(Loosening(path, f"{old} -> {new}"))
    elif kind in ("true", "false"):
        weak_value = kind == "false"  # "true": False is the weak value; "false": True is
        if old is not weak_value and new is weak_value:
            out.append(Loosening(path, f"{old} -> {new}"))
    elif kind == "superset":
        if removed := set(old) - set(new):
            out.append(Loosening(path, f"removes {sorted(map(str, removed))}"))
    elif kind == "subset":
        if added := set(new) - set(old):
            out.append(Loosening(path, f"adds {sorted(map(str, added))}"))
    elif kind == "scope":
        if (not old and new) or (old and new and not set(new) >= set(old)):
            out.append(Loosening(path, f"narrows {sorted(map(str, old)) or 'all tools'}"))
    elif kind.startswith("enum:"):
        order = kind[5:].split(",")
        if order.index(str(getattr(new, "value", new))) < order.index(
            str(getattr(old, "value", old))
        ):
            out.append(Loosening(path, f"{old} -> {new}"))
    elif kind in ("map_lower", "map_higher", "caps"):
        out.extend(_compare_map(kind, path, old, new))
    elif kind == "interval":
        (old_start, old_end), (new_start, new_end) = old, new
        if new_start < old_start or new_end > old_end:
            out.append(Loosening(path, f"{tuple(old)} -> {tuple(new)} (wider business hours)"))
    elif kind == "bindings":
        for tool, binding in old.items():
            if tool not in new:
                out.append(Loosening(f"{path}.{tool}", "binding removed"))
            elif new[tool] != binding:
                out.append(Loosening(f"{path}.{tool}", "binding changed"))
    else:  # fixed, or anything unclassified
        out.append(Loosening(path, f"{old} -> {new} (this field must not change)"))
    return out


def _compare_map(
    kind: str, path: str, old: Mapping[str, Any], new: Mapping[str, Any]
) -> list[Loosening]:
    out: list[Loosening] = []
    if kind == "caps":
        if old and not new:
            return [Loosening(path, "removes every cap (switches the scope off)")]
        if not old:
            return []
    per_key = "higher" if kind == "map_higher" else "lower"
    for key, value in new.items():
        if key not in old:
            out.append(Loosening(f"{path}.{key}", "adds a currency that failed closed before"))
        else:
            out.extend(_compare(per_key, f"{path}.{key}", old[key], value))
    return out


def _compare_rules(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[Loosening]:
    out: list[Loosening] = []
    for rule_id in sorted(set(old) | set(new)):
        before, after = old.get(rule_id), new.get(rule_id)
        was = (True, "enforce", None) if before is None else _rule_tuple(before)
        now = (True, "enforce", None) if after is None else _rule_tuple(after)
        base = f"rules[{rule_id}]"
        if was[0] and not now[0]:
            out.append(Loosening(f"{base}.enabled", "disabled"))
        if was[1] == "enforce" and now[1] != "enforce":
            out.append(Loosening(f"{base}.mode", "enforce -> observe_only (shadow)"))
        if was[2] and now[2] and _SEVERITY_RANK[now[2]] < _SEVERITY_RANK[was[2]]:
            out.append(Loosening(f"{base}.severity", f"{was[2]} -> {now[2]}"))
    return out


def _rule_tuple(rule: Mapping[str, Any]) -> tuple[bool, str, str | None]:
    mode = rule["mode"]
    return rule["enabled"], str(getattr(mode, "value", mode)), rule["severity"]


def find_loosenings(base: PolicyConfig, merged: PolicyConfig) -> list[Loosening]:
    """Every way ``merged`` is weaker than ``base`` (empty if it only tightens or keeps)."""
    old, new = base.model_dump(), merged.model_dump()
    out: list[Loosening] = []
    for field in new:
        if field in _SECTIONS:
            for name in new[field]:
                path = f"{field}.{name}"
                kind = DIRECTIONS.get(path, "fixed")
                out.extend(_compare(kind, path, old[field][name], new[field][name]))
            continue
        kind = DIRECTIONS.get(field, "fixed")
        if kind == "rules":
            out.extend(_compare_rules(old[field], new[field]))
        elif kind == "exemptions":
            known = {ex["id"]: ex for ex in old[field]}
            for ex in new[field]:
                if known.get(ex["id"]) != ex:
                    out.append(Loosening(f"exemptions[{ex['id']}]", "added or changed"))
        else:
            out.extend(_compare(kind, field, old[field], new[field]))
    return out


def _matches(path: str, patterns: Iterable[str]) -> str | None:
    """First pattern that matches ``path``. ``*`` is the only wildcard (it matches any text);
    ``[`` ``]`` and ``.`` are literal, so ``rules[*].mode`` and ``exemptions[ex-1]`` work."""
    for pattern in patterns:
        regex = ".*".join(re.escape(part) for part in pattern.split("*"))
        if re.fullmatch(regex, path):
            return pattern
    return None


def check_tightening(
    base: PolicyConfig,
    merged: PolicyConfig,
    *,
    loosen: Iterable[str],
    locked: Iterable[str],
) -> tuple[str, ...]:
    """Raise unless every loosening is listed in ``loosen`` and none is ``locked``.

    Returns the accepted loosenings as ``"path: detail"`` strings for the provenance record. A
    ``loosen`` entry that loosens nothing is also an error: a stale entry would silently
    pre-authorise a future loosening.
    """
    loosen, locked = list(loosen), list(locked)
    problems: list[str] = []
    accepted: list[str] = []
    used: set[str] = set()
    for item in find_loosenings(base, merged):
        if (lock := _matches(item.path, locked)) is not None:
            problems.append(f"{item.path} ({item.detail}) is locked by the base policy ({lock})")
        elif (allow := _matches(item.path, loosen)) is None:
            problems.append(
                f"{item.path} ({item.detail}) loosens the base policy; add it to `loosen:` to allow"
            )
        else:
            used.add(allow)
            accepted.append(f"{item.path}: {item.detail}")
    problems.extend(
        f"loosen entry {pattern!r} does not loosen anything"
        for pattern in loosen
        if pattern not in used
    )
    if problems:
        raise PolicyLoadError("overlay is not allowed:\n  - " + "\n  - ".join(problems))
    return tuple(accepted)


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Resolved:
    config: PolicyConfig
    raw: dict[str, Any]
    chain: tuple[str, ...]
    locked: tuple[str, ...]
    loosened: tuple[str, ...]


def _read(path: Path) -> tuple[dict[str, Any], str]:
    try:
        blob = path.read_bytes()
        raw = yaml.safe_load(blob.decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyLoadError(f"cannot read policy {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"policy {path} must be a YAML mapping")
    return raw, hashlib.sha256(blob).hexdigest()


def _string_list(value: Any, key: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PolicyLoadError(f"{path}: `{key}` must be a list of field paths")
    return [v.strip() for v in value]


def _merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Deep merge, overlay wins. ``key+: [..]`` appends to the base list instead of replacing."""
    for key, value in overlay.items():
        if key.endswith("+"):
            real = key[:-1]
            current = base.get(real, [])
            if not isinstance(current, list) or not isinstance(value, list):
                raise PolicyLoadError(f"`{key}` can only append a list to a list")
            base[real] = current + [v for v in value if v not in current]
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _parent_path(extends: Any, overlay: Path) -> Path:
    if not isinstance(extends, str) or not extends.strip():
        raise PolicyLoadError(f"{overlay}: `extends` must name a preset id or a file")
    name = extends.strip()
    if _PRESET_ID.match(name):
        from . import default_preset_path  # lazy: the package imports this module's parent

        candidate = default_preset_path().parent / f"{name}.yaml"
    else:
        candidate = (overlay.parent / name).resolve()
    if not candidate.is_file():
        raise PolicyLoadError(f"{overlay}: extends {name!r} but {candidate} does not exist")
    return candidate


def _validate(raw: dict[str, Any], path: Path) -> PolicyConfig:
    try:
        return PolicyConfig.model_validate(raw)
    except ValidationError as exc:
        raise PolicyLoadError(f"invalid policy {path}:\n{exc}") from exc


def _resolve(path: Path, seen: tuple[Path, ...], depth: int) -> _Resolved:
    here = path.resolve()
    if depth > MAX_DEPTH:
        raise PolicyLoadError(f"policy extends chain is deeper than {MAX_DEPTH}: {path}")
    if here in seen:
        raise PolicyLoadError(f"policy extends itself through a cycle: {path}")
    raw, digest = _read(path)
    # Provenance is always recomputed by the loader, so a copy written into a file (for example
    # from `show-policy` output) is ignored rather than trusted.
    raw.pop("provenance", None)
    meta = {key: raw.pop(key) for key in META_KEYS if key in raw}
    label = f"{path.name}@sha256:{digest[:12]}"
    loosen = _string_list(meta.get("loosen"), "loosen", path)
    locked = _string_list(meta.get("locked"), "locked", path)

    if "extends" not in meta:
        if loosen:
            raise PolicyLoadError(f"{path}: `loosen` only makes sense with `extends`")
        return _Resolved(_validate(raw, path), raw, (label,), tuple(locked), ())

    parent = _resolve(_parent_path(meta["extends"], path), (*seen, here), depth + 1)
    merged_raw = _merge(copy.deepcopy(parent.raw), raw)
    config = _validate(merged_raw, path)
    all_locked = tuple(dict.fromkeys((*parent.locked, *locked)))
    accepted = check_tightening(parent.config, config, loosen=loosen, locked=parent.locked)
    return _Resolved(
        config, merged_raw, (*parent.chain, label), all_locked, (*parent.loosened, *accepted)
    )


def load_policy_file(path: Path) -> PolicyConfig:
    """Load a policy file, resolving ``extends`` and enforcing tighten-only overlays."""
    resolved = _resolve(Path(path), (), 0)
    provenance = PolicyProvenance(
        chain=resolved.chain, loosened=resolved.loosened, locked=resolved.locked
    )
    return resolved.config.model_copy(update={"provenance": provenance})
