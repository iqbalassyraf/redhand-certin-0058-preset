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
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from itertools import islice
from pathlib import Path
from zoneinfo import ZoneInfo

from .models import (
    Decision,
    HITLPolicy,
    MicroTxPolicy,
    OffHoursPolicy,
    PolicyConfig,
    TokenClaims,
    VelocityPolicy,
)

_log = logging.getLogger(__name__)

# Stable rule identifiers, namespaced by advisory and kill-chain stage.
R_QUARANTINED = "CIAD-2026-0058.R0.agent_quarantined"
R_TOKEN_INVALID = "CIAD-2026-0058.R1.token_invalid"  # noqa: S105 - rule id, not a credential
R_ENV_PIVOT = "CIAD-2026-0058.R1.staging_to_prod_pivot"
R_MICRO_TX = "CIAD-2026-0058.R2.micro_tx_probe"
R_VELOCITY = "CIAD-2026-0058.R2.velocity_burst"
R_TOOL_NOT_PINNED = "CIAD-2026-0058.R3.tool_not_pinned"
R_HITL = "CIAD-2026-0058.R3.hitl_required"
R_OFF_HOURS_HITL = "CIAD-2026-0058.R4.off_hours_hitl_required"
R_OFF_HOURS = "CIAD-2026-0058.R4.off_hours_tightened"

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


class OffHoursEvaluator:
    """Decides whether ``now`` is a low-monitoring window and picks the matching thresholds."""

    def __init__(self, policy: PolicyConfig) -> None:
        self._p: OffHoursPolicy = policy.off_hours
        self._tz = ZoneInfo(self._p.timezone)
        factor = Decimal(str(self._p.tighten_factor))
        self._normal = EffectivePolicy(
            off_hours_reason=None,
            max_probes=policy.micro_tx.max_probes,
            max_velocity_calls=policy.velocity.max_calls,
            hitl_thresholds=dict(policy.hitl.thresholds),
            mandatory_hitl=False,
        )
        self._tight = EffectivePolicy(
            off_hours_reason="",  # filled per call
            max_probes=max(1, math.ceil(policy.micro_tx.max_probes * self._p.tighten_factor)),
            max_velocity_calls=max(
                1, math.floor(policy.velocity.max_calls * self._p.tighten_factor)
            ),
            hitl_thresholds={k: v * factor for k, v in policy.hitl.thresholds.items()},
            mandatory_hitl=self._p.mandatory_hitl,
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
        t = self._tight
        return EffectivePolicy(
            why, t.max_probes, t.max_velocity_calls, t.hitl_thresholds, t.mandatory_hitl
        )


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
    """Stage 2: machine-speed enumeration bursts per (agent run, tool)."""

    def __init__(self, policy: VelocityPolicy) -> None:
        self._p = policy
        self._windows = KeyedSlidingWindow(policy.window_seconds, maxlen=policy.max_calls + 1)

    def observe(
        self, agent_run_id: str, tool_name: str, now: float, effective: EffectivePolicy
    ) -> Violation | None:
        count = self._windows.hit((agent_run_id, tool_name), now)
        if count <= effective.max_velocity_calls:
            return None
        tightened = (
            f" [tightened for {effective.off_hours_reason}]" if effective.off_hours_reason else ""
        )
        return Violation(
            R_VELOCITY,
            "high",
            2,
            Decision.BLOCK,
            f"{tool_name!r} called more than {effective.max_velocity_calls} times within "
            f"{self._p.window_seconds:g}s{tightened}",
            quarantine=True,
        )


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
