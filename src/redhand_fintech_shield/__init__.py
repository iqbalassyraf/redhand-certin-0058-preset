"""redhand-certin-0058-preset: deterministic runtime defense against CERT-In CIAD-2026-0058."""

from __future__ import annotations

from pathlib import Path

from . import adapters
from .approvals import ApprovalIssuer, ApprovalVerifier, NonceRegistry
from .audit import AuditLog, ChainVerificationReport, HashChainedAuditLog
from .context import extract_tool_call_context
from .crypto import AgentTokenIssuer, AgentTokenVerifier
from .detectors import QuarantineRegistry, QuarantineTracker
from .exceptions import (
    AgentQuarantinedError,
    AuditChainError,
    CumulativeCapError,
    HITLRequiredError,
    MicroTxProbeError,
    MissingContextError,
    NewBeneficiaryError,
    PolicyLoadError,
    SequenceViolationError,
    ShieldError,
    StructuringError,
    TokenInvalidError,
    TokenPivotError,
    ToolNotPinnedError,
    VelocityExceededError,
)
from .gateway import MCPGateway, ToolDefinition
from .interceptor import Evaluation, Shield, redhand_guard
from .models import (
    AggregationPolicy,
    ApprovalPolicy,
    ApprovalRequest,
    AuditRecord,
    CumulativeCapPolicy,
    Decision,
    Env,
    Exemption,
    ExemptionMatch,
    M42Finding,
    Mode,
    PolicyConfig,
    PolicyProvenance,
    RuleOverride,
    TokenClaims,
    ToolBinding,
    ToolBindingsPolicy,
    ToolCallContext,
)
from .protocols import (
    AuditLogBackend,
    Clock,
    MonotonicClock,
    NonceStore,
    NullTelemetrySink,
    QuarantineBackend,
    TelemetrySink,
    ToolExecutor,
)

__version__ = "0.1.0"

_PRESET_NAME = "certin_ciad_2026_0058.yaml"


def default_preset_path() -> Path:
    """Locate the bundled preset (repo checkout first, then an installed wheel's shared data)."""
    import sys

    candidates = [
        Path(__file__).resolve().parents[2] / "presets" / _PRESET_NAME,
        Path(sys.prefix) / "share" / "redhand-certin-0058-preset" / "presets" / _PRESET_NAME,
    ]
    for c in candidates:
        if c.is_file():
            return c
    raise PolicyLoadError(f"bundled preset {_PRESET_NAME} not found; pass an explicit path")


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """Load a policy YAML, defaulting to the bundled CIAD-2026-0058 preset."""
    return PolicyConfig.from_yaml(path if path is not None else default_preset_path())


__all__ = [
    "AgentQuarantinedError",
    "AgentTokenIssuer",
    "AgentTokenVerifier",
    "AggregationPolicy",
    "ApprovalIssuer",
    "ApprovalPolicy",
    "ApprovalRequest",
    "ApprovalVerifier",
    "AuditChainError",
    "AuditLog",
    "AuditLogBackend",
    "AuditRecord",
    "ChainVerificationReport",
    "Clock",
    "CumulativeCapError",
    "CumulativeCapPolicy",
    "Decision",
    "Env",
    "Evaluation",
    "Exemption",
    "ExemptionMatch",
    "HITLRequiredError",
    "HashChainedAuditLog",
    "M42Finding",
    "MCPGateway",
    "MicroTxProbeError",
    "MissingContextError",
    "Mode",
    "MonotonicClock",
    "NewBeneficiaryError",
    "NonceRegistry",
    "NonceStore",
    "NullTelemetrySink",
    "PolicyConfig",
    "PolicyLoadError",
    "PolicyProvenance",
    "QuarantineBackend",
    "QuarantineRegistry",
    "QuarantineTracker",
    "RuleOverride",
    "SequenceViolationError",
    "Shield",
    "ShieldError",
    "StructuringError",
    "TelemetrySink",
    "TokenClaims",
    "TokenInvalidError",
    "TokenPivotError",
    "ToolBinding",
    "ToolBindingsPolicy",
    "ToolCallContext",
    "ToolDefinition",
    "ToolExecutor",
    "ToolNotPinnedError",
    "VelocityExceededError",
    "__version__",
    "adapters",
    "default_preset_path",
    "extract_tool_call_context",
    "load_policy",
    "redhand_guard",
]
