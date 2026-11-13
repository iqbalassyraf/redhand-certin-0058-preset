"""Extensibility protocols and seams for redhand-fintech-shield.

Narrow, clean typing.Protocol interfaces decoupling the deterministic security
shield from storage, telemetry, time, and execution backends.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from .models import AuditRecord, M42Finding


@runtime_checkable
class AuditLogBackend(Protocol):
    """Protocol for tamper-evident audit log storage backends."""

    def append(self, body: dict[str, Any]) -> AuditRecord:
        """Chain and record one audit entry. Returns the validated AuditRecord."""
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
    "NullTelemetrySink",
    "QuarantineBackend",
    "TelemetrySink",
    "ToolExecutor",
]
