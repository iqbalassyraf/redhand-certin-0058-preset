"""Resolve a tool's amount, currency and beneficiary(ies) from its arguments.

The money rules only work if they see the field a tool really pays from. A tool is described by a
:class:`~redhand_fintech_shield.models.ToolBinding`; tools without one fall back to the conventional
names (``amount``, ``currency``, ``beneficiary``) unless the policy turns that off.

Everything here is deterministic and bounded: paths are a tiny dotted syntax (no filters, no
recursion), lists are capped by ``max_items``, and a field that cannot be resolved completely is
reported as unresolved instead of guessed. Unresolved fields are handled fail-closed by the
detectors on protected tools.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from .models import ToolBinding, ToolBindingsPolicy

_Selector = str | int | None  # None: plain key, "*": every list element, int: one element


@dataclass(frozen=True, slots=True)
class MoneyFields:
    """What the money rules need from one call. ``None`` / empty means unresolved."""

    amount: Decimal | float | None = None
    currency: str | None = None
    beneficiary: str | None = None
    beneficiaries: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default=())


@functools.lru_cache(maxsize=512)
def _parse(path: str) -> tuple[tuple[str, _Selector], ...]:
    segments: list[tuple[str, _Selector]] = []
    for part in path.split("."):
        if part.endswith("]"):
            key, _, sel = part[:-1].partition("[")
            segments.append((key, "*" if sel == "*" else int(sel)))
        else:
            segments.append((part, None))
    return tuple(segments)


def resolve_path(root: Any, path: str, max_items: int) -> tuple[list[Any], bool]:
    """Return ``(values, complete)`` for ``path`` inside ``root``.

    ``complete`` is False if any branch of the path was missing, null or of the wrong shape, so a
    list whose second payment lacks an amount is not mistaken for a smaller payment.
    Raises ``ValueError`` if a list is larger than ``max_items``.
    """
    complete = True
    frontier: list[Any] = [root]
    for key, sel in _parse(path):
        nxt: list[Any] = []
        for node in frontier:
            if not isinstance(node, dict) or key not in node:
                complete = False
                continue
            child = node[key]
            if sel is None:
                nxt.append(child)
            elif sel == "*":
                if not isinstance(child, (list, tuple)):
                    complete = False
                    continue
                if len(child) > max_items:
                    raise ValueError(f"{key!r} holds more than {max_items} items")
                nxt.extend(child)
            elif isinstance(sel, int) and isinstance(child, (list, tuple)) and sel < len(child):
                nxt.append(child[sel])
            else:
                complete = False
        if len(nxt) > max_items:
            raise ValueError(f"path {path!r} expands to more than {max_items} items")
        frontier = nxt
    if any(v is None for v in frontier):
        complete = False
        frontier = [v for v in frontier if v is not None]
    return frontier, complete


def _sum_amounts(values: list[Any]) -> Decimal | float:
    """Sum amounts. A float is returned as-is so ``ToolCallContext`` rejects it."""
    total = Decimal(0)
    try:
        for v in values:
            if isinstance(v, float):
                return v
            if isinstance(v, bool) or not isinstance(v, (str, int, Decimal)):
                raise ValueError(f"invalid amount of type {type(v).__name__}")
            try:
                d = Decimal(str(v))
            except InvalidOperation as exc:
                raise ValueError(f"invalid decimal amount: {v}") from exc
            if not d.is_finite():
                raise ValueError(f"amount must be finite: {v}")
            if d < 0:
                # A negative element would let a bulk call net itself below every threshold.
                raise ValueError(f"negative amount in a bulk call: {v}")
            total += d
    except ArithmeticError as exc:
        raise ValueError("amount is out of range") from exc
    return total


def _bound_money(arguments: dict[str, Any], binding: ToolBinding) -> MoneyFields:
    notes: list[str] = []
    amount: Decimal | float | None = None
    currency: str | None = binding.fixed_currency
    beneficiary: str | None = None
    beneficiaries: tuple[str, ...] = ()

    if binding.amount is not None:
        values, complete = resolve_path(arguments, binding.amount, binding.max_items)
        if values and complete:
            amount = _sum_amounts(values)
        else:
            notes.append(f"amount path {binding.amount!r} is missing or incomplete")

    if binding.currency is not None:
        values, complete = resolve_path(arguments, binding.currency, binding.max_items)
        codes = {str(v).strip().upper() for v in values}
        if complete and len(codes) == 1 and "" not in codes:
            currency = next(iter(codes))
        else:
            notes.append(f"currency path {binding.currency!r} is missing, incomplete or mixed")

    if binding.beneficiary is not None:
        values, complete = resolve_path(arguments, binding.beneficiary, binding.max_items)
        names = tuple(dict.fromkeys(str(v).strip() for v in values))
        if complete and names and "" not in names:
            beneficiary, beneficiaries = names[0], names
        else:
            notes.append(f"beneficiary path {binding.beneficiary!r} is missing or incomplete")

    if amount is None and currency is not None:
        # Without an amount a currency means nothing to the rules, and ToolCallContext refuses the
        # pair. Keep the call evaluable (and audited) instead of rejecting it before evaluation.
        notes.append(f"currency {currency!r} dropped because the amount is unresolved")
        currency = None
    return MoneyFields(amount, currency, beneficiary, beneficiaries, tuple(notes))


def _conventional_money(
    arguments: dict[str, Any], meta: dict[str, Any], arg_meta: dict[str, Any]
) -> MoneyFields:
    """The original behaviour: ``amount``, ``currency`` and ``beneficiary`` by name."""
    raw_amount = arguments.get("amount")
    amount: Decimal | float | None
    if raw_amount is None:
        amount = None
    elif isinstance(raw_amount, float):
        amount = raw_amount
    else:
        try:
            amount = Decimal(str(raw_amount))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(f"invalid decimal amount: {raw_amount}") from exc

    raw_currency = arguments.get("currency")
    currency = str(raw_currency).upper() if raw_currency is not None else None

    raw_beneficiary = (
        arguments.get("beneficiary") or meta.get("beneficiary") or arg_meta.get("beneficiary")
    )
    beneficiary: str | None = None
    if raw_beneficiary is not None:
        stripped = str(raw_beneficiary).strip()
        beneficiary = stripped if stripped else None
    return MoneyFields(amount, currency, beneficiary)


def resolve_money_fields(
    tool_name: str,
    arguments: dict[str, Any],
    meta: dict[str, Any],
    arg_meta: dict[str, Any],
    bindings: ToolBindingsPolicy | None,
) -> MoneyFields:
    """Pick the binding for ``tool_name`` (or the conventional fallback) and resolve it."""
    if bindings is not None and (binding := bindings.tools.get(tool_name)) is not None:
        # A bound tool is judged by its bound fields only: a decoy ``amount`` argument is ignored.
        return _bound_money(arguments, binding)
    if bindings is not None and not bindings.legacy_fallback:
        return MoneyFields(notes=("no binding for this tool and legacy_fallback is off",))
    return _conventional_money(arguments, meta, arg_meta)
