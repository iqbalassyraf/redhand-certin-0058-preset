"""Typed exceptions raised by the shield.

Every block-type exception carries the :class:`~redhand_fintech_shield.models.M42Finding`
that triggered it so callers can react programmatically (alerting, HITL routing, retries).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import M42Finding


class ShieldError(Exception):
    """Base class for every error raised by this package."""

    def __init__(self, message: str, finding: M42Finding | None = None) -> None:
        super().__init__(message)
        self.finding = finding


class PolicyLoadError(ShieldError):
    """The policy preset could not be read or failed schema validation."""


class MissingContextError(ShieldError):
    """A guarded tool was called without a valid ``ToolCallContext`` (fail closed)."""


class AuditChainError(ShieldError):
    """The audit log is unreadable, corrupt, or fails hash-chain verification."""


class AgentQuarantinedError(ShieldError):
    """The agent run is quarantined; every call is refused."""


class TokenInvalidError(ShieldError):
    """Token failed signature, expiry, issuer, TTL, or run-binding verification."""


class TokenPivotError(ShieldError):
    """Credential minted for one environment was used against another (stage 1)."""


class ToolNotPinnedError(ShieldError):
    """Tool is not in the token's cryptographically pinned ``allowed_tools`` (stage 3)."""


class MicroTxProbeError(ShieldError):
    """Micro-transaction probing loop detected (stage 2)."""


class VelocityExceededError(ShieldError):
    """Per-second call velocity exceeded (enumeration burst, stage 2)."""


class HITLRequiredError(ShieldError):
    """Human-in-the-loop step-up is required for this call (stages 3 and 4)."""
