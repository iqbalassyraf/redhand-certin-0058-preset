"""Extensibility protocols and seams for redhand-fintech-shield.

Narrow, clean typing.Protocol interfaces decoupling the deterministic security
shield from storage, telemetry, time, and execution backends.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal, Protocol, runtime_checkable

from .models import AuditRecord, M42Finding, TokenClaims


@runtime_checkable
class AuditLogBackend(Protocol):
    """Protocol for tamper-evident audit log storage backends."""

    def append(self, body: dict[str, Any]) -> AuditRecord | None:
        """Chain and record one entry. Returns the validated AuditRecord (None: no chain kept)."""
        ...  # pragma: no cover

    def close(self) -> None:
        """Flush and close underlying storage or transport resources."""
        ...  # pragma: no cover

    @property
    def tail_hash(self) -> str:
        """Current SHA-256 tail hash of the log chain."""
        ...  # pragma: no cover


@runtime_checkable
class QuarantineBackend(Protocol):
    """Protocol for agent run containment/quarantine backends."""

    def add(self, agent_run_id: str, reason: str, ts: datetime | None = None) -> bool:
        """Quarantine an agent run. Returns True if newly added, False if already quarantined."""
        ...  # pragma: no cover

    def is_quarantined(self, agent_run_id: str) -> bool:
        """Return True if the specified agent run is quarantined."""
        ...  # pragma: no cover

    def reason(self, agent_run_id: str) -> str | None:
        """Return the quarantine reason for the specified agent run, or None."""
        ...  # pragma: no cover


class WindowStoreFull(Exception):
    """A window store cannot hold another distinct key; detectors then fail closed."""


@runtime_checkable
class WindowStore(Protocol):
    """Protocol for the sliding-window state behind the stateful detectors.

    Windows are keyed by ``(namespace, key)``. ``window`` is the span in seconds and ``maxlen`` the
    most events kept (the newest); both are constant per namespace. ``now`` is on the shield's
    time base. Each operation must be atomic. A new key that cannot be stored raises
    :class:`WindowStoreFull`; a store with no such limit never raises it.
    """

    def hit(
        self, namespace: str, key: tuple[str, ...], now: float, *, window: float, maxlen: int
    ) -> int:
        """Record an event at ``now``; return how many events are in the window (capped)."""
        ...  # pragma: no cover

    def count(self, namespace: str, key: tuple[str, ...], now: float, *, window: float) -> int:
        """Events in the window at ``now``, recording nothing (0 for an unknown key)."""
        ...  # pragma: no cover

    def add(
        self,
        namespace: str,
        key: tuple[str, ...],
        now: float,
        amount: Decimal,
        *,
        window: float,
        maxlen: int,
    ) -> tuple[int, Decimal, bool]:
        """Record ``amount``; return ``(entries, total, saturated)``.

        ``saturated`` is True when the window was already full and its oldest entry was dropped,
        so the total undercounts: detectors treat that as fail-closed.
        """
        ...  # pragma: no cover

    def snapshot(
        self, namespace: str, key: tuple[str, ...], now: float, *, window: float
    ) -> tuple[int, Decimal]:
        """``(entries, total)`` in the window, recording nothing ``(0, 0)`` for an unknown key."""
        ...  # pragma: no cover

    def has_room(
        self, namespace: str, keys: Sequence[tuple[str, ...]], now: float, *, window: float
    ) -> bool:
        """True if recording one entry for **every** key in ``keys`` will not raise
        :class:`WindowStoreFull`. Asked once for the whole set, so a detector that writes several
        keys per payment (run and subject) cannot get half of them stored."""
        ...  # pragma: no cover


@runtime_checkable
class NonceStore(Protocol):
    """Protocol for the single-use ledger behind per-transaction approvals."""

    def consume(self, nonce: str, expires_at: int) -> bool:
        """Atomically mark ``nonce`` spent. True if it was unused, False if already spent.

        ``expires_at`` (epoch seconds) lets a store forget the nonce once the approval carrying it
        could no longer verify. A store that cannot record the nonce must raise or return False:
        an approval is honoured only when this returns True.
        """
        ...  # pragma: no cover


@runtime_checkable
class TokenVerifier(Protocol):
    """Protocol for turning an agent token into verified claims, or raising ``TokenInvalidError``.

    ``AgentTokenVerifier`` (Ed25519 JWTs) and ``HostVerifiedOnly`` (for embedded hosts) both
    satisfy it.
    """

    def verify(self, token: str) -> TokenClaims:
        """Return the verified claims of ``token``; raise ``TokenInvalidError`` otherwise."""
        ...  # pragma: no cover


@runtime_checkable
class RevocationStore(Protocol):
    """Protocol for revoking agent tokens by token id, subject or agent run."""

    def reason(self, jti: str, subject: str, agent_run_id: str) -> str | None:
        """Why a token with these identifiers is revoked, or None if it is not."""
        ...  # pragma: no cover

    def revoke(
        self,
        kind: Literal["jti", "subject", "run"],
        value: str,
        reason: str,
        expires_at: int | None = None,
    ) -> bool:
        """Revoke ``value``; ``expires_at`` (epoch seconds) lets a store forget it later."""
        ...  # pragma: no cover


@runtime_checkable
class Clock(Protocol):
    """Protocol for wall-clock time sources."""

    def now(self) -> datetime:
        """Return current wall-clock datetime (timezone-aware UTC recommended)."""
        ...  # pragma: no cover


@runtime_checkable
class MonotonicClock(Protocol):
    """Protocol for monotonic time sources."""

    def monotonic(self) -> float:
        """Return a monotonic clock reading in fractional seconds."""
        ...  # pragma: no cover


@runtime_checkable
class TelemetrySink(Protocol):
    """Protocol for RedHand M4.2 finding telemetry egress."""

    def emit(self, finding: M42Finding) -> None:
        """Emit an M42Finding to telemetry/SIEM/metrics pipeline."""
        ...  # pragma: no cover


class NullAuditLog:
    """An audit sink that keeps nothing, for a host whose own ledger already records every decision.

    The shield still hands every decision to ``append``; this discards it. It has no chain, so
    ``tail_hash`` is the genesis value and ``verify-audit`` has nothing to check. Use it only when
    another tamper-evident record exists (for example RedHand's Black Box), never to avoid auditing.
    """

    def append(self, body: dict[str, Any]) -> AuditRecord | None:
        """Discard the entry."""
        return None

    def close(self) -> None:
        """Nothing to close."""

    @property
    def tail_hash(self) -> str:
        return "0" * 64


class NullTelemetrySink:
    """Default no-op telemetry sink."""

    def emit(self, finding: M42Finding) -> None:
        """Discard the finding silently."""
        pass


@runtime_checkable
class ToolExecutor(Protocol):
    """Protocol for synchronous and asynchronous tool invocation backends."""

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Synchronously execute the specified tool with arguments and context."""
        ...  # pragma: no cover

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Asynchronously execute the specified tool with arguments and context."""
        ...  # pragma: no cover


__all__ = [
    "AuditLogBackend",
    "Clock",
    "MonotonicClock",
    "NonceStore",
    "NullTelemetrySink",
    "QuarantineBackend",
    "RevocationStore",
    "TelemetrySink",
    "ToolExecutor",
    "WindowStore",
    "WindowStoreFull",
]
