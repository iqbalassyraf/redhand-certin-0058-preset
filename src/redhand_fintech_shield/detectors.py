"""Deterministic detectors for the CRAFTY FALCON kill chain.

Nothing here performs I/O on the hot path (apart from the optional quarantine journal write on
the rare quarantine event) and nothing calls an LLM. State-holding classes are NOT thread-safe on
their own: :class:`~redhand_fintech_shield.interceptor.Shield` serializes access with one lock.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from itertools import islice
from pathlib import Path
from zoneinfo import ZoneInfo

from .models import (
    AggregationPolicy,
    CumulativeCapPolicy,
    Decision,
    HITLPolicy,
    MicroTxPolicy,
    NewBeneficiaryPolicy,
    OffHoursPolicy,
    PolicyConfig,
    SequencePolicy,
    StructuringPolicy,
    TokenClaims,
    VelocityPolicy,
)
from .normalize import canonical_beneficiary

_log = logging.getLogger(__name__)

# Stable rule identifiers, namespaced by advisory and kill-chain stage.
R_QUARANTINED = "CIAD-2026-0058.R0.agent_quarantined"
R_TOKEN_INVALID = "CIAD-2026-0058.R1.token_invalid"  # noqa: S105 - rule id, not a credential
R_ENV_PIVOT = "CIAD-2026-0058.R1.staging_to_prod_pivot"
R_MICRO_TX = "CIAD-2026-0058.R2.micro_tx_probe"
R_VELOCITY = "CIAD-2026-0058.R2.velocity_burst"
R_STRUCTURING = "CIAD-2026-0058.R2.structuring"
R_SEQUENCE = "CIAD-2026-0058.R2.recon_to_payment_sequence"
R_TOOL_NOT_PINNED = "CIAD-2026-0058.R3.tool_not_pinned"
R_HITL = "CIAD-2026-0058.R3.hitl_required"
R_NEW_BENEFICIARY = "CIAD-2026-0058.R3.new_beneficiary_high_value"
R_OFF_HOURS_HITL = "CIAD-2026-0058.R4.off_hours_hitl_required"
R_OFF_HOURS = "CIAD-2026-0058.R4.off_hours_tightened"
R_CUMULATIVE_CAP = "CIAD-2026-0058.R2.cumulative_cap"
R_APPROVAL_ACCEPTED = "CIAD-2026-0058.R3.approval_accepted"
R_APPROVAL_REJECTED = "CIAD-2026-0058.R3.approval_rejected"
R_LEGACY_STEP_UP = "CIAD-2026-0058.R3.legacy_run_wide_step_up"

Severity = str  # "low" | "medium" | "high" | "critical"


@dataclass(frozen=True, slots=True)
class Violation:
    """A detector verdict; the interceptor turns it into an M4.2 finding."""

    rule_id: str
    severity: Severity
    stage: int
    decision: Decision
    detail: str
    quarantine: bool = False
    # Also contain every run of the token subject (a subject-scope aggregation tripped).
    quarantine_subject: bool = False


# --------------------------------------------------------------------------------------
# Stage 4: off-hours policy adjustment (pure function of policy x clock)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """Thresholds actually applied to one call, after off-hours adjustment."""

    off_hours_reason: str | None
    max_probes: int
    max_velocity_calls: int
    hitl_thresholds: dict[str, Decimal]
    mandatory_hitl: bool
    structuring_thresholds: dict[str, Decimal]
    new_beneficiary_thresholds: dict[str, Decimal]
    max_total_calls: int | None = None
    cap_run: dict[str, Decimal] = field(default_factory=dict)
    cap_subject: dict[str, Decimal] = field(default_factory=dict)


class OffHoursEvaluator:
    """Decides whether ``now`` is a low-monitoring window and picks the matching thresholds."""

    def __init__(self, policy: PolicyConfig) -> None:
        self._p: OffHoursPolicy = policy.off_hours
        self._tz = ZoneInfo(self._p.timezone)
        factor = Decimal(str(self._p.tighten_factor))
        total = policy.velocity.max_total_calls
        cap = policy.cumulative_cap
        self._normal = EffectivePolicy(
            off_hours_reason=None,
            max_probes=policy.micro_tx.max_probes,
            max_velocity_calls=policy.velocity.max_calls,
            hitl_thresholds=dict(policy.hitl.thresholds),
            mandatory_hitl=False,
            structuring_thresholds=dict(policy.structuring.thresholds),
            new_beneficiary_thresholds=dict(policy.new_beneficiary.thresholds),
            max_total_calls=total,
            cap_run=dict(cap.per_run),
            cap_subject=dict(cap.per_subject),
        )
        self._tight = EffectivePolicy(
            off_hours_reason="",  # filled per call
            max_probes=max(1, math.ceil(policy.micro_tx.max_probes * self._p.tighten_factor)),
            max_velocity_calls=max(
                1, math.floor(policy.velocity.max_calls * self._p.tighten_factor)
            ),
            hitl_thresholds={k: v * factor for k, v in policy.hitl.thresholds.items()},
            mandatory_hitl=self._p.mandatory_hitl,
            structuring_thresholds={
                k: v * factor for k, v in policy.structuring.thresholds.items()
            },
            new_beneficiary_thresholds={
                k: v * factor for k, v in policy.new_beneficiary.thresholds.items()
            },
            max_total_calls=(
                None if total is None else max(1, math.floor(total * self._p.tighten_factor))
            ),
            cap_run={k: v * factor for k, v in cap.per_run.items()},
            cap_subject={k: v * factor for k, v in cap.per_subject.items()},
        )

    def reason(self, now: datetime) -> str | None:
        """Return why ``now`` is off-hours, or ``None`` during normal business hours."""
        if not self._p.enabled:
            return None
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        local = now.astimezone(self._tz)
        local_date: date = local.date()
        if local.weekday() in self._p.weekend_days:
            return f"weekend ({local.strftime('%A')} {local_date.isoformat()} local)"
        if local_date in self._p.holidays:
            return f"public holiday ({local_date.isoformat()})"
        start, end = self._p.business_hours
        if not (start <= local.hour < end):
            clock_time = local.strftime("%H:%M")
            return f"outside business hours ({clock_time} local, window {start:02d}-{end:02d})"
        return None

    def effective(self, now: datetime) -> EffectivePolicy:
        why = self.reason(now)
        if why is None:
            return self._normal
        return replace(self._tight, off_hours_reason=why)


# --------------------------------------------------------------------------------------
# Sliding windows
# --------------------------------------------------------------------------------------


class SlidingWindowCounter:
    """Count of events in the trailing window; ``deque`` of monotonic stamps, bounded size."""

    __slots__ = ("_stamps", "_window")

    def __init__(self, window_seconds: float, maxlen: int) -> None:
        self._window = window_seconds
        self._stamps: deque[float] = deque(maxlen=maxlen)

    def hit(self, now: float) -> int:
        """Record an event at ``now`` and return how many events are in the window (capped)."""
        stamps = self._stamps
        cutoff = now - self._window
        while stamps and stamps[0] <= cutoff:
            stamps.popleft()
        stamps.append(now)
        return len(stamps)

    def count(self, now: float) -> int:
        """Return how many events are in the trailing window without recording a new event."""
        stamps = self._stamps
        cutoff = now - self._window
        while stamps and stamps[0] <= cutoff:
            stamps.popleft()
        return len(stamps)

    def newest(self) -> float | None:
        return self._stamps[-1] if self._stamps else None

    def __len__(self) -> int:
        return len(self._stamps)


class KeyedSlidingWindow:
    """One bounded :class:`SlidingWindowCounter` per key, with amortized idle-key eviction."""

    def __init__(
        self,
        window_seconds: float,
        maxlen: int,
        *,
        sweep_every: int = 256,
        sweep_batch: int = 256,
    ) -> None:
        self._window = window_seconds
        self._maxlen = maxlen
        self._counters: dict[Hashable, SlidingWindowCounter] = {}
        self._sweep_every = sweep_every
        self._sweep_batch = sweep_batch
        self._ops = 0

    def hit(self, key: Hashable, now: float) -> int:
        counter = self._counters.get(key)
        if counter is None:
            counter = self._counters[key] = SlidingWindowCounter(self._window, self._maxlen)
        count = counter.hit(now)
        self._ops += 1
        if self._ops % self._sweep_every == 0:
            self._sweep(now)
        return count

    def count(self, key: Hashable, now: float) -> int:
        """Return the active count for ``key`` at ``now`` without recording a new event."""
        counter = self._counters.get(key)
        if counter is None:
            return 0
        n = counter.count(now)
        if n == 0:
            del self._counters[key]
        return n

    def _sweep(self, now: float) -> None:
        """Bounded rotating sweep: examine a few keys, drop idle ones, rotate survivors."""
        cutoff = now - self._window
        for key in list(islice(self._counters, self._sweep_batch)):
            counter = self._counters[key]
            newest = counter.newest()
            if newest is None or newest <= cutoff:
                del self._counters[key]
            else:
                self._counters[key] = self._counters.pop(key)

    def __len__(self) -> int:
        return len(self._counters)


# --------------------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------------------


class MicroTxProbeDetector:
    """Stage 2: rapid micro-value payments used to verify unauthorized fund flows."""

    def __init__(self, policy: MicroTxPolicy) -> None:
        self._p = policy
        self._windows = KeyedSlidingWindow(policy.window_seconds, maxlen=policy.max_probes)

    def observe(
        self,
        agent_run_id: str,
        amount: Decimal | None,
        currency: str | None,
        now: float,
        effective: EffectivePolicy,
    ) -> Violation | None:
        if amount is None:
            return None
        ceiling = self._p.ceilings.get(currency) if currency else None
        # Fail closed: an unknown or missing currency cannot be shown to be above the probe ceiling.
        if ceiling is not None and amount > ceiling:
            return None
        count = self._windows.hit(agent_run_id, now)
        if count < effective.max_probes:
            return None
        basis = (
            f"<= {ceiling} {currency}"
            if ceiling is not None
            else f"currency {currency or 'MISSING'!r} has no configured ceiling (fail-closed)"
        )
        tightened = (
            f" [tightened for {effective.off_hours_reason}]" if effective.off_hours_reason else ""
        )
        return Violation(
            R_MICRO_TX,
            "critical",
            2,
            Decision.BLOCK,
            f"{count} micro-value payment(s) ({amount} {currency or '?'}; {basis}) within "
            f"{self._p.window_seconds:g}s, limit {effective.max_probes}{tightened}",
            quarantine=True,
        )


class VelocityDetector:
    """Stage 2: machine-speed enumeration bursts per (agent run, tool) and per run overall."""

    def __init__(self, policy: VelocityPolicy) -> None:
        self._p = policy
        self._windows = KeyedSlidingWindow(policy.window_seconds, maxlen=policy.max_calls + 1)
        # Rotating between tools keeps every per-tool count low; the all-tools window does not.
        self._total = (
            KeyedSlidingWindow(policy.window_seconds, maxlen=policy.max_total_calls + 1)
            if policy.max_total_calls is not None
            else None
        )

    def observe(
        self, agent_run_id: str, tool_name: str, now: float, effective: EffectivePolicy
    ) -> Violation | None:
        count = self._windows.hit((agent_run_id, tool_name), now)
        total = self._total.hit(agent_run_id, now) if self._total is not None else 0
        tightened = (
            f" [tightened for {effective.off_hours_reason}]" if effective.off_hours_reason else ""
        )
        if count > effective.max_velocity_calls:
            return Violation(
                R_VELOCITY,
                "high",
                2,
                Decision.BLOCK,
                f"{tool_name!r} called more than {effective.max_velocity_calls} times within "
                f"{self._p.window_seconds:g}s{tightened}",
                quarantine=True,
            )
        limit = effective.max_total_calls
        if self._total is not None and limit is not None and total > limit:
            return Violation(
                R_VELOCITY,
                "high",
                2,
                Decision.BLOCK,
                f"more than {limit} calls across all tools within "
                f"{self._p.window_seconds:g}s (tool rotation){tightened}",
                quarantine=True,
            )
        return None


class HighValueGate:
    """Stages 3 and 4: HITL step-up on settlement/disbursement endpoints. Stateless."""

    def __init__(self, policy: HITLPolicy) -> None:
        self._p = policy

    def evaluate(
        self,
        tool_name: str,
        amount: Decimal | None,
        currency: str | None,
        claims: TokenClaims | None,
        effective: EffectivePolicy,
    ) -> Violation | None:
        if tool_name not in self._p.protected_tools:
            return None

        base = self._p.thresholds.get(currency) if currency else None
        reason: str | None = None
        rule, stage = R_HITL, 3
        if amount is None:
            reason = "protected endpoint called without an amount (fail-closed)"
        elif base is None:
            reason = f"currency {currency or 'MISSING'!r} has no configured threshold (fail-closed)"
        elif amount > base:
            reason = f"amount {amount} {currency} exceeds {base}"
        elif effective.off_hours_reason is not None:
            rule, stage = R_OFF_HOURS_HITL, 4
            tight = effective.hitl_thresholds.get(currency or "", base)
            if effective.mandatory_hitl:
                reason = f"mandatory HITL during {effective.off_hours_reason}"
            elif amount > tight:
                reason = (
                    f"amount {amount} {currency} exceeds tightened threshold {tight} "
                    f"during {effective.off_hours_reason}"
                )
        if reason is None:
            return None
        if claims is not None and claims.hitl_step_up:
            return None
        return Violation(rule, "high", stage, Decision.HITL_REQUIRED, f"{tool_name!r}: {reason}")


class _WindowSum:
    """Bounded O(1)-amortized sliding-window sum of Decimal amounts."""

    __slots__ = ("_entries", "_maxlen", "_total", "_window")

    def __init__(self, window_seconds: float, maxlen: int) -> None:
        self._window = window_seconds
        self._maxlen = maxlen
        self._entries: deque[tuple[float, Decimal]] = deque()
        self._total = Decimal("0")

    def _expire(self, now: float) -> None:
        entries = self._entries
        cutoff = now - self._window
        while entries and entries[0][0] <= cutoff:
            _, old = entries.popleft()
            self._total -= old

    def add(self, now: float, amount: Decimal) -> tuple[int, Decimal, bool]:
        self._expire(now)
        entries = self._entries
        saturated = len(entries) >= self._maxlen
        if saturated:
            _, dropped = entries.popleft()
            self._total -= dropped
        entries.append((now, amount))
        self._total += amount
        return len(entries), self._total, saturated

    def snapshot(self, now: float) -> tuple[int, Decimal]:
        """Entries and total in the window at ``now``, without recording anything."""
        self._expire(now)
        return len(self._entries), self._total

    def newest(self) -> float | None:
        return self._entries[-1][0] if self._entries else None


class _WindowTable:
    """Keyed :class:`_WindowSum` windows with amortised idle eviction and a hard key limit.

    The key space can be attacker controlled (a payee id), so it is bounded: at the limit, expired
    windows are purged (at most once a second, so a full table cannot be turned into a CPU sink)
    and if there is still no room the caller must fail closed.
    """

    def __init__(
        self,
        window_seconds: float,
        *,
        max_entries: int,
        max_keys: int,
        sweep_every: int,
        sweep_batch: int,
    ) -> None:
        self.window = window_seconds
        self.max_entries = max_entries
        self._max_keys = max_keys
        self._sweep_every = sweep_every
        self._sweep_batch = sweep_batch
        self._windows: dict[tuple[str, str, str], _WindowSum] = {}
        self._ops = 0
        self._last_purge = -math.inf

    def get(self, key: tuple[str, str, str]) -> _WindowSum | None:
        return self._windows.get(key)

    def has_room(self, now: float) -> bool:
        if len(self._windows) < self._max_keys:
            return True
        if now - self._last_purge >= 1.0:
            self._last_purge = now
            cutoff = now - self.window
            for key in [
                k for k, w in self._windows.items() if (n := w.newest()) is None or n <= cutoff
            ]:
                del self._windows[key]
        return len(self._windows) < self._max_keys

    def get_or_create(self, key: tuple[str, str, str]) -> _WindowSum:
        win = self._windows.get(key)
        if win is None:
            win = self._windows[key] = _WindowSum(self.window, self.max_entries)
        return win

    def tick(self, now: float) -> None:
        self._ops += 1
        if self._ops % self._sweep_every == 0:
            cutoff = now - self.window
            for key in list(islice(self._windows, self._sweep_batch)):
                win = self._windows[key]
                newest = win.newest()
                if newest is None or newest <= cutoff:
                    del self._windows[key]
                else:
                    self._windows[key] = self._windows.pop(key)

    def __len__(self) -> int:
        return len(self._windows)


def _convert(
    aggregation: AggregationPolicy | None, amount: Decimal, currency: str | None
) -> tuple[Decimal, str]:
    """Amount and currency key to aggregate under: the base currency if convertible."""
    if aggregation is not None and (converted := aggregation.to_base(amount, currency)):
        return converted
    return amount, currency or ""


def _payees(beneficiaries: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(c for c in map(canonical_beneficiary, beneficiaries) if c))


class StructuringDetector:
    """Stage 2: split-transaction structuring (smurfing).

    Payments are added up per agent run and, if enabled in ``scopes``, per token subject and per
    payee across runs, so a fresh run id or a different payee does not start a fresh window.
    """

    def __init__(
        self,
        policy: StructuringPolicy,
        *,
        aggregation: AggregationPolicy | None = None,
        max_entries: int = 16384,
        sweep_every: int = 256,
        sweep_batch: int = 256,
    ) -> None:
        self._p = policy
        self._agg = aggregation
        self._max_entries = max_entries
        self._table = _WindowTable(
            policy.window_seconds,
            max_entries=max_entries,
            max_keys=policy.max_keys,
            sweep_every=sweep_every,
            sweep_batch=sweep_batch,
        )

    def observe(
        self,
        agent_run_id: str,
        tool_name: str,
        amount: Decimal | None,
        currency: str | None,
        now: float,
        effective: EffectivePolicy,
        claims: TokenClaims | None = None,
        *,
        subject: str | None = None,
        beneficiaries: tuple[str, ...] = (),
    ) -> Violation | None:
        del claims  # Structuring is never bypassed by run-wide hitl_step_up.
        if not self._p.enabled or amount is None:
            return None
        if self._p.protected_tools and tool_name not in self._p.protected_tools:
            return None

        amt, ccy = _convert(self._agg, amount, currency)
        scopes: list[tuple[str, str]] = [("run", agent_run_id)]
        if "subject" in self._p.scopes and subject:
            scopes.append(("subject", subject))
        if "beneficiary" in self._p.scopes and len(payees := _payees(beneficiaries)) == 1:
            scopes.append(("beneficiary", payees[0]))

        found: list[tuple[str, Violation]] = []
        for scope, ident in scopes:
            v = self._observe_scope(scope, ident, ccy, currency, amt, now, effective)
            if v is not None:
                found.append((scope, v))
        self._table.tick(now)
        if not found:
            return None
        first = found[0][1]
        if any(scope == "subject" for scope, _ in found):
            first = replace(first, quarantine_subject=True)
        return first

    def _observe_scope(
        self,
        scope: str,
        ident: str,
        ccy: str,
        original_currency: str | None,
        amount: Decimal,
        now: float,
        effective: EffectivePolicy,
    ) -> Violation | None:
        where = "" if scope == "run" else f" [{scope} {ident!r}, across runs]"
        key = (scope, ident, ccy)
        win = self._table.get(key)
        if win is None:
            if not self._table.has_room(now):
                return Violation(
                    R_STRUCTURING,
                    "critical",
                    2,
                    Decision.BLOCK,
                    f"structuring tracker is full (fail-closed){where}",
                    quarantine=True,
                )
            win = self._table.get_or_create(key)
        count, total, saturated = win.add(now, amount)

        if saturated:
            return Violation(
                R_STRUCTURING,
                "critical",
                2,
                Decision.BLOCK,
                f"structuring window reached capacity ({self._max_entries} entries) within "
                f"{self._p.window_seconds:g}s (fail-closed){where}",
                quarantine=True,
            )

        if count < self._p.min_tx_count:
            return None

        threshold = effective.structuring_thresholds.get(ccy) if ccy else None
        shown = ccy or "MISSING"
        if threshold is None:
            return Violation(
                R_STRUCTURING,
                "critical",
                2,
                Decision.BLOCK,
                f"{count} transactions totaling {total} {shown} within "
                f"{self._p.window_seconds:g}s; currency {shown!r} has no "
                f"configured structuring threshold (fail-closed){where}",
                quarantine=True,
            )

        if total > threshold:
            tightened = (
                f" [tightened for {effective.off_hours_reason}]"
                if effective.off_hours_reason
                else ""
            )
            converted = (
                f" (converted to {ccy} from {original_currency})"
                if original_currency and ccy != original_currency
                else ""
            )
            return Violation(
                R_STRUCTURING,
                "critical",
                2,
                Decision.BLOCK,
                f"{count} transactions totaling {total} {ccy} within "
                f"{self._p.window_seconds:g}s exceeds structuring threshold "
                f"{threshold}{tightened}{converted}{where}",
                quarantine=True,
            )
        return None


class CumulativeCapDetector:
    """Stage 2: slow drain. A rolling cap on what one run and one subject may move.

    ``check`` is read-only and ``record`` adds the payment, so a call that is refused or waiting
    for step-up is not counted; the interceptor runs both inside one critical section.
    """

    def __init__(
        self,
        policy: CumulativeCapPolicy,
        *,
        aggregation: AggregationPolicy | None = None,
        max_entries: int = 16384,
        sweep_every: int = 256,
        sweep_batch: int = 256,
    ) -> None:
        self._p = policy
        self._agg = aggregation
        self._max_entries = max_entries
        self._table = _WindowTable(
            policy.window_seconds,
            max_entries=max_entries,
            max_keys=policy.max_keys,
            sweep_every=sweep_every,
            sweep_batch=sweep_batch,
        )

    def _applies(self, tool_name: str, amount: Decimal | None) -> bool:
        if not self._p.enabled or amount is None:
            return False
        return not self._p.protected_tools or tool_name in self._p.protected_tools

    def _scopes(self, agent_run_id: str, subject: str | None) -> list[tuple[str, str]]:
        scopes: list[tuple[str, str]] = []
        if self._p.per_run:
            scopes.append(("run", agent_run_id))
        if self._p.per_subject and subject:
            scopes.append(("subject", subject))
        return scopes

    def _violation(self, scope: str, ident: str, detail: str) -> Violation:
        block = self._p.action == "block"
        where = "" if scope == "run" else f" [{scope} {ident!r}, across runs]"
        return Violation(
            R_CUMULATIVE_CAP,
            "high",
            2,
            Decision.BLOCK if block else Decision.HITL_REQUIRED,
            f"{detail}{where}",
            quarantine=block,
            quarantine_subject=block and scope == "subject",
        )

    def check(
        self,
        agent_run_id: str,
        tool_name: str,
        amount: Decimal | None,
        currency: str | None,
        now: float,
        effective: EffectivePolicy,
        *,
        subject: str | None = None,
    ) -> Violation | None:
        if amount is None or not self._applies(tool_name, amount):
            return None
        amt, ccy = _convert(self._agg, amount, currency)
        shown = ccy or "MISSING"
        for scope, ident in self._scopes(agent_run_id, subject):
            caps = effective.cap_run if scope == "run" else effective.cap_subject
            cap = caps.get(ccy) if ccy else None
            if cap is None:
                return self._violation(
                    scope, ident, f"currency {shown!r} has no configured {scope} cap (fail-closed)"
                )
            win = self._table.get((scope, ident, ccy))
            if win is None:
                if not self._table.has_room(now):
                    return self._violation(
                        scope, ident, "cumulative-cap tracker is full (fail-closed)"
                    )
                size, current = 0, Decimal(0)
            else:
                size, current = win.snapshot(now)
            if size >= self._max_entries:
                return self._violation(
                    scope,
                    ident,
                    f"cumulative-cap window reached capacity ({self._max_entries} entries) "
                    "(fail-closed)",
                )
            projected = current + amt
            if projected > cap:
                tightened = (
                    f" [tightened for {effective.off_hours_reason}]"
                    if effective.off_hours_reason
                    else ""
                )
                return self._violation(
                    scope,
                    ident,
                    f"{scope} total would reach {projected} {ccy} within "
                    f"{self._p.window_seconds:g}s, above the cap {cap}{tightened}",
                )
        return None

    def record(
        self,
        agent_run_id: str,
        tool_name: str,
        amount: Decimal | None,
        currency: str | None,
        now: float,
        *,
        subject: str | None = None,
    ) -> None:
        if amount is None or not self._applies(tool_name, amount):
            return
        amt, ccy = _convert(self._agg, amount, currency)
        for scope, ident in self._scopes(agent_run_id, subject):
            self._table.get_or_create((scope, ident, ccy)).add(now, amt)
        self._table.tick(now)


class NewBeneficiaryDetector:
    """Stage 3: high-value disbursement to an unseen/untrusted beneficiary. Stateless."""

    def __init__(
        self,
        policy: NewBeneficiaryPolicy,
        protected_tools: frozenset[str] | None = None,
    ) -> None:
        self._p = policy
        self._protected_tools = protected_tools

    def evaluate(
        self,
        tool_name: str,
        beneficiary: str | None,
        amount: Decimal | None,
        currency: str | None,
        claims: TokenClaims | None,
        effective: EffectivePolicy,
        beneficiaries: tuple[str, ...] = (),
    ) -> Violation | None:
        raw = ((beneficiary,) if beneficiary else ()) + beneficiaries
        payees = tuple(dict.fromkeys(c for c in map(canonical_beneficiary, raw) if c))
        if not self._p.enabled or not payees:
            return None
        if self._protected_tools is not None and tool_name not in self._protected_tools:
            return None
        # A bulk call is judged by every payee: one unknown payee among known ones is enough.
        unknown = [b for b in payees if b not in self._p.known_beneficiaries]
        if not unknown:
            return None
        beneficiary = unknown[0]
        more = f" (+{len(unknown) - 1} more new)" if len(unknown) > 1 else ""
        if self._p.action == "hitl_required" and claims is not None and claims.hitl_step_up:
            return None

        base = self._p.thresholds.get(currency) if currency else None
        if effective.off_hours_reason is not None and currency and base is not None:
            threshold: Decimal | None = effective.new_beneficiary_thresholds.get(currency, base)
        else:
            threshold = base

        reason: str | None = None
        if amount is None:
            reason = (
                f"new beneficiary {beneficiary!r}{more} on protected endpoint without an amount "
                "(fail-closed)"
            )
        elif threshold is None:
            reason = (
                f"new beneficiary {beneficiary!r}{more} with currency {currency or 'MISSING'!r} "
                "has no configured threshold (fail-closed)"
            )
        elif amount > threshold:
            tightened = (
                f" [tightened for {effective.off_hours_reason}]"
                if effective.off_hours_reason
                else ""
            )
            reason = (
                f"new beneficiary {beneficiary!r}{more} with amount {amount} {currency} "
                f"exceeds {threshold}{tightened}"
            )
        if reason is None:
            return None

        decision = Decision.BLOCK if self._p.action == "block" else Decision.HITL_REQUIRED
        return Violation(R_NEW_BENEFICIARY, "high", 3, decision, f"{tool_name!r}: {reason}")


class SequenceRuleDetector:
    """Stage 2: reconnaissance-to-payment kill-chain sequence detection."""

    def __init__(self, policy: SequencePolicy) -> None:
        self._p = policy
        self._windows = KeyedSlidingWindow(policy.window_seconds, maxlen=policy.min_recon_calls)

    def observe(self, agent_run_id: str, tool_name: str, now: float) -> Violation | None:
        if not self._p.enabled:
            return None
        if tool_name in self._p.recon_tools:
            self._windows.hit(agent_run_id, now)
            return None
        if tool_name in self._p.payment_tools:
            recon_count = self._windows.count(agent_run_id, now)
            if recon_count >= self._p.min_recon_calls:
                return Violation(
                    R_SEQUENCE,
                    "high",
                    2,
                    Decision.BLOCK,
                    f"{tool_name!r} called after {recon_count} recon call(s) within "
                    f"{self._p.window_seconds:g}s (limit {self._p.min_recon_calls})",
                    quarantine=True,
                )
        return None


# --------------------------------------------------------------------------------------
# Quarantine
# --------------------------------------------------------------------------------------


class QuarantineRegistry:
    """Set of contained agent runs, optionally journaled so a crash does not free an agent."""

    def __init__(self, journal_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._reasons: dict[str, str] = {}
        self._journal_path = journal_path
        if journal_path is not None:
            self._replay(journal_path)

    def _replay(self, path: Path) -> None:
        if not path.exists():
            return
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    self._reasons[str(entry["agent_run_id"])] = str(entry["reason"])
                except (ValueError, KeyError, TypeError):
                    # A torn final line after a crash must not stop the shield from starting.
                    _log.warning("ignoring unreadable quarantine journal line %s:%d", path, lineno)

    def add(self, agent_run_id: str, reason: str, ts: datetime | None = None) -> bool:
        """Quarantine a run. Returns ``True`` if it was newly added."""
        with self._lock:
            if agent_run_id in self._reasons:
                return False
            self._reasons[agent_run_id] = reason
            if self._journal_path is not None:
                stamp = (ts or datetime.now(UTC)).isoformat()
                line = json.dumps(
                    {"agent_run_id": agent_run_id, "reason": reason, "ts": stamp},
                    separators=(",", ":"),
                )
                with self._journal_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            return True

    def is_quarantined(self, agent_run_id: str) -> bool:
        return agent_run_id in self._reasons

    def reason(self, agent_run_id: str) -> str | None:
        return self._reasons.get(agent_run_id)

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._reasons)


# Ergonomic alias conforming to protocol naming
QuarantineTracker = QuarantineRegistry
