"""Pydantic v2 data models: policy configuration, call context, findings, audit records."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .normalize import canonical_beneficiary
from .rules import EXEMPTIBLE_RULES, OVERRIDABLE_RULES, RULE_CATALOG

_STRICT = ConfigDict(frozen=True, extra="forbid")

SUPPORTED_SCHEMA_VERSION = 1  # policy schema this package understands

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Za-z]{3}$", to_upper=True)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]
# Dotted argument path with optional list selectors: ``payee.vpa``, ``payments[*].amount``,
# ``items[0].value``. Deliberately not full JSONPath: no filters, no recursion, nothing that can
# be made expensive by attacker-controlled arguments.
ArgPath = Annotated[
    str,
    StringConstraints(
        max_length=256,
        pattern=(
            r"^[A-Za-z_][A-Za-z0-9_-]*(\[(\*|\d+)\])?"
            r"(\.[A-Za-z_][A-Za-z0-9_-]*(\[(\*|\d+)\])?)*$"
        ),
    ),
]


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
    max_total_calls: int | None = Field(
        default=None,
        ge=1,
        description="Calls across ALL tools per agent run in the window; stops tool rotation.",
    )


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


class StructuringPolicy(BaseModel):
    """Stage 2: split-transaction structuring (smurfing) within a sliding window."""

    model_config = _STRICT

    enabled: bool = True
    protected_tools: frozenset[NonEmptyStr] = frozenset()
    thresholds: dict[CurrencyCode, Decimal] = Field(
        default_factory=lambda: {"USD": Decimal("10000.00")},
        description="Per-currency cumulative amount above which multiple calls trip structuring.",
    )
    window_seconds: float = Field(default=300.0, gt=0)
    min_tx_count: int = Field(default=2, ge=1)
    scopes: frozenset[Literal["run", "subject", "beneficiary"]] = Field(
        default=frozenset({"run"}),
        description=(
            "What payments are aggregated by: the agent run, the token subject (across runs), "
            "and/or one payee (across runs; single-payee calls only)."
        ),
    )
    max_keys: int = Field(
        default=100_000,
        ge=1,
        description="Most distinct windows kept; beyond it the call fails closed.",
    )

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
        return _check_currency_map(v, "structuring.thresholds")

    @field_validator("scopes")
    @classmethod
    def _need_a_scope(cls, v: frozenset[str]) -> frozenset[str]:
        if not v:
            raise ValueError("structuring.scopes must name at least one scope")
        return v


class NewBeneficiaryPolicy(BaseModel):
    """Stage 3: high-value disbursement to an unseen/untrusted beneficiary."""

    model_config = _STRICT

    enabled: bool = True
    thresholds: dict[CurrencyCode, Decimal] = Field(
        default_factory=lambda: {"USD": Decimal("1000.00")},
        description="Per-currency amount above which an unseen beneficiary triggers action.",
    )
    known_beneficiaries: frozenset[NonEmptyStr] = frozenset()
    action: Literal["hitl_required", "block"] = "hitl_required"

    @field_validator("known_beneficiaries")
    @classmethod
    def _canonical_known(cls, v: frozenset[str]) -> frozenset[str]:
        """Store payees in canonical form so they compare equal to canonical call payees."""
        return frozenset(c for c in (canonical_beneficiary(b) for b in v) if c)

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
        return _check_currency_map(v, "new_beneficiary.thresholds")


class SequencePolicy(BaseModel):
    """Stage 2: reconnaissance-to-payment kill-chain sequence detection."""

    model_config = _STRICT

    enabled: bool = True
    recon_tools: frozenset[NonEmptyStr] = frozenset()
    payment_tools: frozenset[NonEmptyStr] = frozenset()
    min_recon_calls: int = Field(default=3, ge=1)
    window_seconds: float = Field(default=30.0, gt=0)


class AggregationPolicy(BaseModel):
    """Optional cross-currency aggregation using operator-supplied static rates.

    With ``base_currency`` set, structuring and cumulative caps add up payments in every currency
    after converting them to the base, so splitting a payout across currencies no longer evades
    them. The rates are approximations the operator must review; a currency with no rate cannot be
    converted and fails closed (it is judged in its own currency, which has no threshold).
    """

    model_config = _STRICT

    base_currency: CurrencyCode | None = None
    rates: dict[CurrencyCode, Decimal] = Field(
        default_factory=dict, description="Units of base currency per one unit of the currency."
    )

    @field_validator("rates", mode="before")
    @classmethod
    def _no_float_rates(cls, v: Any) -> Any:
        if isinstance(v, dict):
            for item in v.values():
                _reject_float(item)
        return v

    @model_validator(mode="after")
    def _valid_rates(self) -> AggregationPolicy:
        for code, rate in self.rates.items():
            if not rate.is_finite() or rate <= 0:
                raise ValueError(f"aggregation.rates[{code}] must be a finite, positive rate")
        if self.base_currency is None and self.rates:
            raise ValueError("aggregation.rates needs aggregation.base_currency")
        if self.base_currency in self.rates:
            raise ValueError("the base currency must not have a rate (it is always 1)")
        return self

    def to_base(self, amount: Decimal, currency: str | None) -> tuple[Decimal, str] | None:
        """Return ``(amount in base, base)``, or None if aggregation is off or cannot convert."""
        if self.base_currency is None or currency is None:
            return None
        if currency == self.base_currency:
            return amount, currency
        rate = self.rates.get(currency)
        if rate is None:
            return None
        try:
            return amount * rate, self.base_currency
        except ArithmeticError:
            return None


class CumulativeCapPolicy(BaseModel):
    """Stage 2: slow drain. A rolling cap on what one run, and one subject, may move."""

    model_config = _STRICT

    enabled: bool = False
    protected_tools: frozenset[NonEmptyStr] = frozenset()
    window_seconds: float = Field(default=86_400.0, gt=0)
    per_run: dict[CurrencyCode, Decimal] = Field(default_factory=dict)
    per_subject: dict[CurrencyCode, Decimal] = Field(default_factory=dict)
    action: Literal["hitl_required", "block"] = "hitl_required"
    max_keys: int = Field(default=100_000, ge=1)

    @field_validator("per_run", "per_subject", mode="before")
    @classmethod
    def _no_floats(cls, v: Any) -> Any:
        if isinstance(v, dict):
            for item in v.values():
                _reject_float(item)
        return v

    @field_validator("per_run", "per_subject")
    @classmethod
    def _valid_caps(cls, v: dict[str, Decimal]) -> dict[str, Decimal]:
        for code, amount in v.items():
            if not amount.is_finite() or amount < 0:
                raise ValueError(f"cap[{code}] must be a finite, non-negative amount")
        return v

    @model_validator(mode="after")
    def _enabled_needs_a_cap(self) -> CumulativeCapPolicy:
        if self.enabled and not (self.per_run or self.per_subject):
            raise ValueError("cumulative_cap is enabled but defines no per_run or per_subject cap")
        return self


class ToolBinding(BaseModel):
    """Where one tool keeps its amount, currency and beneficiary(ies) in its arguments.

    A path that selects a list (``payments[*].amount``) makes the call a bulk call: amounts are
    summed, beneficiaries are all judged, and currencies must agree or the currency is treated as
    unknown (fail-closed). If a bound path is absent, incomplete or ambiguous the field is
    unresolved, which the detectors already treat as fail-closed on protected tools.
    """

    model_config = _STRICT

    amount: ArgPath | None = None
    currency: ArgPath | None = None
    fixed_currency: CurrencyCode | None = Field(
        default=None,
        description="For tools that take no currency argument (for example a domestic-only tool).",
    )
    beneficiary: ArgPath | None = None
    max_items: int = Field(
        default=1000, ge=1, le=100_000, description="Largest list a bound path may expand."
    )

    @model_validator(mode="after")
    def _one_currency_source(self) -> ToolBinding:
        if self.currency is not None and self.fixed_currency is not None:
            raise ValueError("set either currency or fixed_currency, not both")
        return self


class ToolBindingsPolicy(BaseModel):
    """Per-tool argument bindings, so money rules see the field a tool really uses."""

    model_config = _STRICT

    tools: dict[NonEmptyStr, ToolBinding] = Field(default_factory=dict)
    legacy_fallback: bool = Field(
        default=True,
        description=(
            "Tools without a binding fall back to the conventional argument names "
            "(amount, currency, beneficiary). False means unbound tools resolve nothing."
        ),
    )
    require_for_protected: bool = Field(
        default=False,
        description=(
            "Refuse to load a policy in which a protected tool has no binding. A protected tool "
            "is any tool named in hitl, structuring or sequence.payment_tools."
        ),
    )


class ApprovalPolicy(BaseModel):
    """Per-transaction step-up: signed, single-use human approvals bound to one transaction."""

    model_config = _STRICT

    verifier_public_key_path: Path | None = Field(
        default=None,
        description="Approver's Ed25519 public key. Must differ from the agent-token issuer's.",
    )
    issuer: NonEmptyStr = "redhand-approver"
    max_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    nonce_journal_path: Path | None = Field(
        default=None,
        description="Journal of spent nonces, replayed on startup so a restart keeps them spent.",
    )
    max_nonces: int = Field(default=100_000, ge=1)
    allow_legacy_step_up: bool = Field(
        default=True,
        description=(
            "DEPRECATED. Honour the run-wide hitl_step_up token claim as a step-up. Each use is "
            "reported as a finding. Set false once approvers issue per-transaction approvals."
        ),
    )


class ApprovalRequest(BaseModel):
    """What a human approver is asked to sign. Built by the shield, never by the agent."""

    model_config = _STRICT

    request_id: NonEmptyStr
    agent_run_id: NonEmptyStr
    tool_name: NonEmptyStr
    target_env: Env
    amount: Decimal | None = None
    currency: CurrencyCode | None = None
    beneficiaries: tuple[NonEmptyStr, ...] = ()
    arguments_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reasons: tuple[str, ...] = Field(default=(), description="Rule ids that require step-up.")
    details: tuple[str, ...] = ()
    requested_at: datetime


class ApprovalClaims(BaseModel):
    """Verified claims of a signed approval. Everything but ``sub``/``nonce``/times is a binding."""

    model_config = _STRICT

    iss: str
    sub: NonEmptyStr  # the approving human or system
    request_id: str
    agent_run_id: str
    tool_name: str
    target_env: Env
    amount: str | None = None
    currency: str | None = None
    beneficiaries: tuple[str, ...] = ()
    arguments_digest: str | None = None
    nonce: NonEmptyStr
    iat: int
    exp: int


SeverityLabel = Literal["low", "medium", "high", "critical"]


class RuleOverride(BaseModel):
    """Per-rule operator control: run a rule in shadow, switch it off, or re-label it.

    Shadow (``mode: observe_only``) keeps the detector running and reports what it would have done
    (``enforced=False``), but the rule never blocks, quarantines, or asks for an approval. Only
    detector rules can be overridden; identity, pinning, quarantine and approval rules cannot.
    """

    model_config = _STRICT

    enabled: bool = True
    mode: Mode = Mode.ENFORCE
    severity: SeverityLabel | None = None


class ExemptionMatch(BaseModel):
    """Which calls an exemption covers. Every given constraint must hold."""

    model_config = _STRICT

    tools: frozenset[NonEmptyStr] = frozenset()
    subjects: frozenset[NonEmptyStr] = frozenset()
    beneficiaries: frozenset[NonEmptyStr] = Field(
        default=frozenset(),
        description="Canonical payee ids; every payee of the call must be listed.",
    )
    envs: frozenset[Env] = frozenset()

    @field_validator("beneficiaries")
    @classmethod
    def _canonical_payees(cls, v: frozenset[str]) -> frozenset[str]:
        return frozenset(c for c in (canonical_beneficiary(b) for b in v) if c)

    @model_validator(mode="after")
    def _not_blanket(self) -> ExemptionMatch:
        if not (self.tools or self.subjects or self.beneficiaries or self.envs):
            raise ValueError(
                "an exemption must match on at least one of tools/subjects/"
                "beneficiaries/envs (no blanket exemptions)"
            )
        return self


class Exemption(BaseModel):
    """A time-limited, named, audited waiver of a human step-up requirement."""

    model_config = _STRICT

    id: NonEmptyStr
    rules: frozenset[NonEmptyStr] = Field(min_length=1)
    reason: Annotated[str, StringConstraints(min_length=10, strip_whitespace=True)]
    approved_by: NonEmptyStr
    starts_at: AwareDatetime
    expires_at: AwareDatetime
    match: ExemptionMatch

    @field_validator("rules")
    @classmethod
    def _only_step_up_rules(cls, v: frozenset[str]) -> frozenset[str]:
        bad = sorted(v - EXEMPTIBLE_RULES)
        if bad:
            raise ValueError(
                f"exemptions can only waive step-up rules; not waivable: {', '.join(bad)}"
            )
        return v

    @model_validator(mode="after")
    def _ordered(self) -> Exemption:
        if self.expires_at <= self.starts_at:
            raise ValueError(f"exemption {self.id!r}: expires_at must be after starts_at")
        return self


class PolicyProvenance(BaseModel):
    """Where a policy came from. Set only by the loader, never read from a policy file."""

    model_config = _STRICT

    chain: tuple[str, ...] = Field(
        default=(), description="Sources from the root policy to the overlay, with SHA-256."
    )
    loosened: tuple[str, ...] = Field(
        default=(), description="Base limits the overlay deliberately loosened (its loosen: list)."
    )
    locked: tuple[str, ...] = Field(
        default=(), description="Field paths no overlay may loosen, declared by the base."
    )


class TokenKeyConfig(BaseModel):
    """One agent-token verification key in a key ring (see ``crypto.KeyRing``)."""

    model_config = _STRICT

    kid: NonEmptyStr
    public_key_path: Path
    retire_at: AwareDatetime | None = Field(
        default=None, description="Tokens signed with this key stop verifying at this instant."
    )


class PolicyConfig(BaseModel):
    """Declarative policy; loaded from ``presets/certin_ciad_2026_0058.yaml``."""

    model_config = _STRICT

    schema_version: int = Field(
        default=1, ge=1, description="Policy schema version; a newer one than supported is refused."
    )
    preset_id: NonEmptyStr = "certin_ciad_2026_0058"
    preset_version: str | None = Field(
        default=None, description="Semantic version of the preset's content (bump on any change)."
    )
    mode: Mode = Mode.ENFORCE
    issuer: NonEmptyStr = "redhand"
    max_token_ttl_seconds: int = Field(default=3600, ge=1)
    verifier_public_key_path: Path | None = None
    token_keys: tuple[TokenKeyConfig, ...] = Field(
        default=(),
        description="Key ring for rotation; tokens must carry a matching kid. Replaces the single "
        "verifier_public_key_path.",
    )
    audience: NonEmptyStr | None = Field(
        default=None,
        description="If set, tokens must carry this aud claim (binds tokens to this service).",
    )
    revocation_journal_path: Path | None = None
    micro_tx: MicroTxPolicy = Field(default_factory=MicroTxPolicy)
    velocity: VelocityPolicy = Field(default_factory=VelocityPolicy)
    hitl: HITLPolicy = Field(default_factory=HITLPolicy)
    off_hours: OffHoursPolicy = Field(default_factory=OffHoursPolicy)
    structuring: StructuringPolicy = Field(default_factory=StructuringPolicy)
    new_beneficiary: NewBeneficiaryPolicy = Field(default_factory=NewBeneficiaryPolicy)
    sequence: SequencePolicy = Field(default_factory=SequencePolicy)
    tool_bindings: ToolBindingsPolicy = Field(default_factory=ToolBindingsPolicy)
    approval: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    aggregation: AggregationPolicy = Field(default_factory=AggregationPolicy)
    cumulative_cap: CumulativeCapPolicy = Field(default_factory=CumulativeCapPolicy)
    rules: dict[NonEmptyStr, RuleOverride] = Field(default_factory=dict)
    exemptions: tuple[Exemption, ...] = ()
    exemption_max_days: int = Field(default=90, ge=1, le=365)
    provenance: PolicyProvenance | None = None
    quarantine_on_block: bool = True
    audit_path: Path = Path("audit_trail.jsonl")
    audit_fsync: bool = False
    quarantine_journal_path: Path | None = None

    @field_validator("schema_version")
    @classmethod
    def _supported_schema(cls, v: int) -> int:
        if v > SUPPORTED_SCHEMA_VERSION:
            raise ValueError(
                f"policy schema_version {v} is newer than this package supports "
                f"({SUPPORTED_SCHEMA_VERSION}); upgrade redhand-certin-0058-preset"
            )
        return v

    def fingerprint(self) -> str:
        """SHA-256 of the rules this policy puts in force (see ``fingerprint.py``)."""
        from .fingerprint import policy_fingerprint  # lazy: fingerprint imports layers

        return policy_fingerprint(self)

    @property
    def protected_tools(self) -> frozenset[str]:
        """Every tool the money rules treat as protected."""
        return (
            self.hitl.protected_tools
            | self.structuring.protected_tools
            | (self.sequence.payment_tools)
        )

    @model_validator(mode="after")
    def _bindings_cover_protected_tools(self) -> PolicyConfig:
        if self.tool_bindings.require_for_protected:
            missing = sorted(self.protected_tools - set(self.tool_bindings.tools))
            if missing:
                raise ValueError(
                    f"tool_bindings.require_for_protected is set but these protected tools have "
                    f"no binding: {', '.join(missing)}"
                )
        return self

    @model_validator(mode="after")
    def _token_key_sources(self) -> PolicyConfig:
        if self.token_keys and self.verifier_public_key_path is not None:
            raise ValueError("set either token_keys or verifier_public_key_path, not both")
        kids = [k.kid for k in self.token_keys]
        if len(kids) != len(set(kids)):
            raise ValueError("token_keys has a duplicate kid")
        return self

    @model_validator(mode="after")
    def _rules_and_exemptions(self) -> PolicyConfig:
        unknown = sorted(set(self.rules) - OVERRIDABLE_RULES)
        if unknown:
            raise ValueError(
                f"rules can only override detector rules; not overridable: {', '.join(unknown)}"
            )
        seen: set[str] = set()
        limit = timedelta(days=self.exemption_max_days)
        for ex in self.exemptions:
            if ex.id in seen:
                raise ValueError(f"duplicate exemption id {ex.id!r}")
            seen.add(ex.id)
            if ex.expires_at - ex.starts_at > limit:
                raise ValueError(
                    f"exemption {ex.id!r} lasts longer than exemption_max_days "
                    f"({self.exemption_max_days})"
                )
        return self

    @model_validator(mode="after")
    def _aggregation_has_base_limits(self) -> PolicyConfig:
        base = self.aggregation.base_currency
        if base is None:
            return self
        if self.structuring.enabled and base not in self.structuring.thresholds:
            raise ValueError(f"aggregation is on but structuring.thresholds has no {base}")
        cap = self.cumulative_cap
        if cap.enabled:
            for label, caps in (("per_run", cap.per_run), ("per_subject", cap.per_subject)):
                if caps and base not in caps:
                    raise ValueError(f"aggregation is on but cumulative_cap.{label} has no {base}")
        return self

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyConfig:
        """Load and validate a policy file, resolving ``extends``. Unknown keys are rejected."""
        from .layers import load_policy_file  # lazy: layers imports this module

        return load_policy_file(Path(path))


class ToolCallContext(BaseModel):
    """Everything the interceptor needs to judge one tool call."""

    model_config = _STRICT

    agent_run_id: NonEmptyStr
    tool_name: NonEmptyStr
    target_env: Env
    token: str
    amount: Decimal | None = None
    currency: CurrencyCode | None = None
    beneficiary: NonEmptyStr | None = None
    beneficiaries: tuple[NonEmptyStr, ...] = Field(
        default=(),
        description="All distinct payees of a bulk call; ``beneficiary`` is the first of them.",
    )
    approval: str | None = Field(
        default=None, description="Signed per-transaction approval presented with the call."
    )
    arguments_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 of the canonical tool arguments; what an approval binds to.",
    )
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
    policy_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="Fingerprint of the policy that produced this finding.",
    )

    def redacted(self) -> M42Finding:
        """A copy whose ``detail`` is the rule's fixed catalog summary, with no call data in it.

        ``detail`` explains a decision with the call's own values (amounts, payee ids, subjects),
        which a host may not be allowed to store or show. The summary is a fixed sentence per rule,
        so a redacted finding can go to logs, dashboards and telemetry. Every other field is kept.
        """
        summary = next((r.summary for r in RULE_CATALOG if r.id == self.rule_id), None)
        return self.model_copy(update={"detail": summary or "A policy rule fired."})


class TokenClaims(BaseModel):
    """Verified claims of an ephemeral per-run agent token."""

    model_config = _STRICT

    iss: str
    sub: str
    aud: str | None = None
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
    policy_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="Fingerprint of the policy in force; absent in logs written before 3.5.",
    )
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
