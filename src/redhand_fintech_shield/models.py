"""Pydantic v2 data models: policy configuration, call context, findings, audit records."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from .exceptions import PolicyLoadError

_STRICT = ConfigDict(frozen=True, extra="forbid")

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Za-z]{3}$", to_upper=True)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    HITL_REQUIRED = "hitl_required"


class Env(StrEnum):
    PROD = "prod"
    STAGING = "staging"
    TEST = "test"
    DEV = "dev"


class Mode(StrEnum):
    """ENFORCE blocks; OBSERVE_ONLY (RedHand M4.3) emits findings but never blocks."""

    ENFORCE = "enforce"
    OBSERVE_ONLY = "observe_only"


def _reject_float(value: Any) -> Any:
    if isinstance(value, float):
        raise ValueError("monetary values must be str, int or Decimal, never float")
    return value


def _check_currency_map(value: dict[str, Decimal], label: str) -> dict[str, Decimal]:
    if not value:
        raise ValueError(f"{label} must define at least one currency")
    for code, amount in value.items():
        if not amount.is_finite() or amount < 0:
            raise ValueError(f"{label}[{code}] must be a finite, non-negative amount")
    return value


class MicroTxPolicy(BaseModel):
    """Stage 2: micro-transaction probing loop."""

    model_config = _STRICT

    ceilings: dict[CurrencyCode, Decimal] = Field(
        default_factory=lambda: {"USD": Decimal("5.00")},
        description="Per-currency amount at or below which a payment counts as a probe.",
    )
    max_probes: int = Field(default=2, ge=1, description="Trip when this many probes occur.")
    window_seconds: float = Field(default=60.0, gt=0)

    @field_validator("ceilings", mode="before")
    @classmethod
    def _no_floats(cls, v: Any) -> Any:
        if isinstance(v, dict):
            for item in v.values():
                _reject_float(item)
        return v

    @field_validator("ceilings")
    @classmethod
    def _valid_ceilings(cls, v: dict[str, Decimal]) -> dict[str, Decimal]:
        return _check_currency_map(v, "micro_tx.ceilings")


class VelocityPolicy(BaseModel):
    """Stage 2: per-second enumeration-burst detection, keyed by (agent run, tool)."""

    model_config = _STRICT

    max_calls: int = Field(default=20, ge=1)
    window_seconds: float = Field(default=1.0, gt=0)


class HITLPolicy(BaseModel):
    """Stage 3: step-up requirement on settlement/disbursement endpoints."""

    model_config = _STRICT

    thresholds: dict[CurrencyCode, Decimal] = Field(
        default_factory=lambda: {"USD": Decimal("10000.00")},
        description="Per-currency amount strictly above which HITL step-up is required.",
    )
    protected_tools: frozenset[NonEmptyStr] = frozenset()

    @field_validator("thresholds", mode="before")
    @classmethod
    def _no_floats(cls, v: Any) -> Any:
        if isinstance(v, dict):
            for item in v.values():
                _reject_float(item)
        return v

    @field_validator("thresholds")
    @classmethod
    def _valid_thresholds(cls, v: dict[str, Decimal]) -> dict[str, Decimal]:
        return _check_currency_map(v, "hitl.thresholds")


class OffHoursPolicy(BaseModel):
    """Stage 4: low-monitoring windows (weekends, public holidays, outside business hours)."""

    model_config = _STRICT

    enabled: bool = True
    timezone: str = "Asia/Kolkata"
    business_hours: tuple[int, int] = (9, 18)
    weekend_days: frozenset[int] = frozenset({5, 6})  # Monday=0 ... Sunday=6
    holidays: frozenset[date] = frozenset()
    tighten_factor: float = Field(default=0.5, gt=0, le=1)
    mandatory_hitl: bool = True

    @field_validator("timezone")
    @classmethod
    def _valid_tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown IANA timezone {v!r}") from exc
        return v

    @field_validator("business_hours")
    @classmethod
    def _valid_hours(cls, v: tuple[int, int]) -> tuple[int, int]:
        start, end = v
        if not (0 <= start < end <= 24):
            raise ValueError("business_hours must satisfy 0 <= start < end <= 24")
        return v

    @field_validator("weekend_days")
    @classmethod
    def _valid_weekdays(cls, v: frozenset[int]) -> frozenset[int]:
        if any(d < 0 or d > 6 for d in v):
            raise ValueError("weekend_days entries must be 0 (Monday) .. 6 (Sunday)")
        return v


class PolicyConfig(BaseModel):
    """Declarative policy; loaded from ``presets/certin_ciad_2026_0058.yaml``."""

    model_config = _STRICT

    preset_id: NonEmptyStr = "certin_ciad_2026_0058"
    mode: Mode = Mode.ENFORCE
    issuer: NonEmptyStr = "redhand"
    max_token_ttl_seconds: int = Field(default=3600, ge=1)
    verifier_public_key_path: Path | None = None
    micro_tx: MicroTxPolicy = Field(default_factory=MicroTxPolicy)
    velocity: VelocityPolicy = Field(default_factory=VelocityPolicy)
    hitl: HITLPolicy = Field(default_factory=HITLPolicy)
    off_hours: OffHoursPolicy = Field(default_factory=OffHoursPolicy)
    quarantine_on_block: bool = True
    audit_path: Path = Path("audit_trail.jsonl")
    audit_fsync: bool = False
    quarantine_journal_path: Path | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyConfig:
        """Load and validate a policy file. Unknown keys are rejected (fail closed)."""
        p = Path(path)
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyLoadError(f"cannot read policy {p}: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyLoadError(f"policy {p} must be a YAML mapping")
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise PolicyLoadError(f"invalid policy {p}:\n{exc}") from exc


class ToolCallContext(BaseModel):
    """Everything the interceptor needs to judge one tool call."""

    model_config = _STRICT

    agent_run_id: NonEmptyStr
    tool_name: NonEmptyStr
    target_env: Env
    token: str
    amount: Decimal | None = None
    currency: CurrencyCode | None = None
    timestamp: datetime | None = Field(
        default=None,
        description="Caller-claimed time; logged but NEVER trusted. The shield uses its own clock.",
    )
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("amount", mode="before")
    @classmethod
    def _no_float_amount(cls, v: Any) -> Any:
        return _reject_float(v)

    @field_validator("amount")
    @classmethod
    def _sane_amount(cls, v: Decimal | None) -> Decimal | None:
        if v is not None and (not v.is_finite() or v < 0):
            raise ValueError("amount must be a finite, non-negative number")
        return v

    @model_validator(mode="after")
    def _currency_needs_amount(self) -> ToolCallContext:
        if self.currency is not None and self.amount is None:
            raise ValueError("currency given without amount")
        return self


class M42Finding(BaseModel):
    """RedHand M4.2 telemetry finding."""

    model_config = _STRICT

    finding_id: str
    rule_id: str
    severity: Literal["low", "medium", "high", "critical"]
    stage: int = Field(ge=0, le=4)
    decision: Decision
    would_have_blocked: bool
    enforced: bool
    agent_run_id: str
    tool_name: str
    detail: str
    observed_at: datetime


class TokenClaims(BaseModel):
    """Verified claims of an ephemeral per-run agent token."""

    model_config = _STRICT

    iss: str
    sub: str
    agent_run_id: str
    env: Env
    allowed_tools: tuple[str, ...]
    hitl_step_up: bool
    iat: int
    exp: int
    jti: str


class AuditRecord(BaseModel):
    """One line of ``audit_trail.jsonl``; ``record_hash`` is computed last."""

    model_config = _STRICT

    seq: int = Field(ge=0)
    ts: datetime
    mode: Mode
    context: ToolCallContext
    decision: Decision
    findings: list[M42Finding]
    latency_us: int = Field(ge=0)
    tool_outcome: Literal["executed", "blocked", "tool_error"]
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
