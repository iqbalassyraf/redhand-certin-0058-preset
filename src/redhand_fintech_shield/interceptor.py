"""The ``@redhand_guard`` interception pipeline.

Order of evaluation (mirrors the design document)::

    [1] quarantine check  ->  [2] env/token claim pinning  ->  [3] off-hours adjustment
    ->  [4] sliding-window detectors + HITL gate  ->  [5] tool execution  ->  [6] audit log

``evaluate()`` is the single decision core shared by the sync and async wrappers. It never calls
the tool, never raises for policy violations, and takes the same path in both modes: only
:meth:`Shield.guard` decides whether a verdict is actuated (``enforce``) or merely recorded
(``observe_only``, RedHand M4.3).
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, TypeVar, cast

from .approvals import (
    ApprovalVerifier,
    NonceRegistry,
    binding_mismatch,
    build_request,
    payees_of,
)
from .audit import HashChainedAuditLog
from .crypto import AgentTokenVerifier, load_public_key_pem, utcnow
from .detectors import (
    R_APPROVAL_ACCEPTED,
    R_APPROVAL_REJECTED,
    R_CUMULATIVE_CAP,
    R_ENV_PIVOT,
    R_HITL,
    R_LEGACY_STEP_UP,
    R_MICRO_TX,
    R_NEW_BENEFICIARY,
    R_OFF_HOURS,
    R_OFF_HOURS_HITL,
    R_QUARANTINED,
    R_SEQUENCE,
    R_STRUCTURING,
    R_TOKEN_INVALID,
    R_TOOL_NOT_PINNED,
    R_VELOCITY,
    CumulativeCapDetector,
    HighValueGate,
    MicroTxProbeDetector,
    NewBeneficiaryDetector,
    OffHoursEvaluator,
    QuarantineRegistry,
    SequenceRuleDetector,
    StructuringDetector,
    VelocityDetector,
    Violation,
)
from .exceptions import (
    AgentQuarantinedError,
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
from .models import (
    ApprovalRequest,
    AuditRecord,
    Decision,
    M42Finding,
    Mode,
    PolicyConfig,
    TokenClaims,
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
)

_log = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])

_EXCEPTION_FOR_RULE: dict[str, type[ShieldError]] = {
    R_QUARANTINED: AgentQuarantinedError,
    R_TOKEN_INVALID: TokenInvalidError,
    R_ENV_PIVOT: TokenPivotError,
    R_TOOL_NOT_PINNED: ToolNotPinnedError,
    R_MICRO_TX: MicroTxProbeError,
    R_VELOCITY: VelocityExceededError,
    R_STRUCTURING: StructuringError,
    R_SEQUENCE: SequenceViolationError,
    R_HITL: HITLRequiredError,
    R_APPROVAL_REJECTED: HITLRequiredError,
    R_CUMULATIVE_CAP: CumulativeCapError,
    R_NEW_BENEFICIARY: NewBeneficiaryError,
    R_OFF_HOURS_HITL: HITLRequiredError,
}


@dataclass(frozen=True, slots=True)
class Evaluation:
    decision: Decision
    findings: list[M42Finding]
    latency_us: int
    # Present when the call needs step-up: exactly what a human approver is asked to sign.
    approval_request: ApprovalRequest | None = None

    def primary_finding(self) -> M42Finding | None:
        """Return the highest-severity non-ALLOW finding (BLOCK > HITL_REQUIRED)."""
        first_non_allow: M42Finding | None = None
        for f in self.findings:
            if f.decision is Decision.BLOCK:
                return f
            if f.decision is not Decision.ALLOW and first_non_allow is None:
                first_non_allow = f
        return first_non_allow or (self.findings[0] if self.findings else None)


class Shield:
    """Holds policy, detector state, quarantine set and audit log for one protected process."""

    def __init__(
        self,
        policy: PolicyConfig,
        verifier: AgentTokenVerifier | None = None,
        *,
        audit: AuditLogBackend | None = None,
        audit_log: AuditLogBackend | None = None,
        quarantine: QuarantineBackend | None = None,
        quarantine_tracker: QuarantineBackend | None = None,
        telemetry_sink: TelemetrySink | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        nonce_store: NonceStore | None = None,
        clock: Clock | Callable[[], datetime] = utcnow,
        monotonic: MonotonicClock | Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy

        if isinstance(clock, Clock):
            self._clock: Callable[[], datetime] = clock.now
        else:
            self._clock = clock

        if isinstance(monotonic, MonotonicClock):
            self._monotonic: Callable[[], float] = monotonic.monotonic
        else:
            self._monotonic = monotonic

        self._verifier = verifier or self._verifier_from_policy(policy, self._clock)
        self.audit: Any = (
            audit or audit_log or HashChainedAuditLog(policy.audit_path, fsync=policy.audit_fsync)
        )
        self.quarantine: Any = (
            quarantine or quarantine_tracker or QuarantineRegistry(policy.quarantine_journal_path)
        )
        self.telemetry_sink: TelemetrySink = (
            telemetry_sink if telemetry_sink is not None else NullTelemetrySink()
        )

        self._approval_verifier = approval_verifier or self._approval_verifier_from_policy(
            policy, self._clock
        )
        self._check_key_separation()
        self._nonces: NonceStore = nonce_store or NonceRegistry(
            policy.approval.nonce_journal_path,
            max_entries=policy.approval.max_nonces,
            clock=self._clock,
        )
        self._off_hours = OffHoursEvaluator(policy)
        self._micro = MicroTxProbeDetector(policy.micro_tx)
        self._velocity = VelocityDetector(policy.velocity)
        self._structuring = StructuringDetector(policy.structuring, aggregation=policy.aggregation)
        self._cap = CumulativeCapDetector(policy.cumulative_cap, aggregation=policy.aggregation)
        self._sequence = SequenceRuleDetector(policy.sequence)
        self._hitl = HighValueGate(policy.hitl)
        self._new_beneficiary = NewBeneficiaryDetector(
            policy.new_beneficiary,
            protected_tools=policy.hitl.protected_tools,
        )
        self._state_lock = threading.Lock()  # guards the sliding windows only
        self.audit_failures = 0
        self.telemetry_failures = 0
        self.quarantine_failures = 0

    @property
    def audit_log(self) -> AuditLogBackend:
        """Alias for ``self.audit`` conforming to protocol naming."""
        return cast(AuditLogBackend, self.audit)

    @property
    def quarantine_tracker(self) -> QuarantineBackend:
        """Alias for ``self.quarantine`` conforming to protocol naming."""
        return cast(QuarantineBackend, self.quarantine)

    @staticmethod
    def _verifier_from_policy(
        policy: PolicyConfig, clock: Callable[[], datetime]
    ) -> AgentTokenVerifier:
        if policy.verifier_public_key_path is None:
            raise PolicyLoadError(
                "no verifier supplied and policy.verifier_public_key_path is not set"
            )
        return AgentTokenVerifier(
            load_public_key_pem(policy.verifier_public_key_path),
            policy.issuer,
            max_ttl_seconds=policy.max_token_ttl_seconds,
            clock=clock,
        )

    @staticmethod
    def _approval_verifier_from_policy(
        policy: PolicyConfig, clock: Callable[[], datetime]
    ) -> ApprovalVerifier | None:
        if policy.approval.verifier_public_key_path is None:
            return None
        return ApprovalVerifier(
            load_public_key_pem(policy.approval.verifier_public_key_path),
            policy.approval.issuer,
            max_ttl_seconds=policy.approval.max_ttl_seconds,
            clock=clock,
        )

    def _check_key_separation(self) -> None:
        """An approver key equal to the token issuer's would let the issuer approve its own runs."""
        approver = getattr(self._approval_verifier, "key_fingerprint", None)
        issuer = getattr(self._verifier, "key_fingerprint", None)
        if approver is not None and approver == issuer:
            raise PolicyLoadError(
                "the approval verifier key must differ from the agent-token verifier key"
            )

    def _resolve_step_up(
        self, ctx: ToolCallContext, claims: TokenClaims, pending: list[Violation]
    ) -> tuple[bool, list[Violation]]:
        """Decide whether the pending HITL requirements are satisfied.

        Returns ``(cleared, extra_findings)``. A per-transaction approval is tried first, then
        (only if the policy still allows it) the deprecated run-wide ``hitl_step_up`` claim.
        """
        extra: list[Violation] = []
        if ctx.approval is not None:
            reason, accepted = self._spend_approval(ctx)
            if reason is None:
                extra.append(
                    Violation(
                        R_APPROVAL_ACCEPTED,
                        "low",
                        3,
                        Decision.ALLOW,
                        f"per-transaction approval accepted ({accepted})",
                    )
                )
                return True, extra
            extra.append(
                Violation(
                    R_APPROVAL_REJECTED,
                    "high",
                    3,
                    Decision.HITL_REQUIRED,
                    f"approval not honoured: {reason}",
                )
            )
        if extra:
            # A rejected per-transaction approval must not silently fall through to the old flag.
            return False, extra
        if claims.hitl_step_up and self.policy.approval.allow_legacy_step_up:
            rules = ", ".join(sorted({v.rule_id.rsplit(".", 1)[-1] for v in pending}))
            extra.append(
                Violation(
                    R_LEGACY_STEP_UP,
                    "low",
                    3,
                    Decision.ALLOW,
                    f"run-wide hitl_step_up satisfied {rules} (deprecated: use per-transaction "
                    "approvals)",
                )
            )
            return True, extra
        return False, extra

    def _spend_approval(self, ctx: ToolCallContext) -> tuple[str | None, str]:
        """Verify and spend the approval: ``(None, who)`` on success, else ``(reason, "")``."""
        verifier = self._approval_verifier
        if verifier is None or ctx.approval is None:
            return "no approval verifier is configured (fail-closed)", ""
        try:
            approval = verifier.verify(ctx.approval)
        except ValueError as exc:
            return str(exc), ""
        if (mismatch := binding_mismatch(approval, ctx)) is not None:
            return mismatch, ""
        try:
            fresh = self._nonces.consume(approval.nonce, approval.exp)
        except Exception:
            _log.exception("approval nonce store failed")
            return "approval store unavailable (fail-closed)", ""
        if not fresh:
            return "approval already used or the nonce store is full", ""
        return None, f"request {approval.request_id} approved by {approval.sub!r}"

    # ------------------------------------------------------------------------------
    # Decision core
    # ------------------------------------------------------------------------------

    def evaluate(self, ctx: ToolCallContext) -> Evaluation:
        """Judge one call. Pure with respect to the tool; mutates only detector state."""
        t0 = time.perf_counter_ns()
        now_dt = self._clock()
        now = self._monotonic()
        enforce = self.policy.mode is Mode.ENFORCE
        violations: list[Violation] = []

        # [1] Quarantine check. In enforce mode a quarantined run is refused immediately, which
        # also stops an attacker from flooding the audit log; in observe mode evaluation continues.
        if (reason := self.quarantine.reason(ctx.agent_run_id)) is not None:
            violations.append(
                Violation(
                    R_QUARANTINED,
                    "critical",
                    0,
                    Decision.BLOCK,
                    f"agent run is quarantined: {reason}",
                )
            )
            if enforce:
                return self._finish(ctx, violations, now_dt, t0)

        # [2] Env / token claim pinning. Verification is CPU-bound and runs outside the lock.
        claims: TokenClaims | None = None
        try:
            claims = self._verifier.verify(ctx.token)
            if claims.agent_run_id != ctx.agent_run_id:
                claims = None
                raise TokenInvalidError("token is bound to a different agent run")
        except TokenInvalidError as exc:
            violations.append(Violation(R_TOKEN_INVALID, "critical", 1, Decision.BLOCK, str(exc)))

        # Detectors key their state on the agent run id. That id is only trustworthy once the token
        # has been verified, so unauthenticated calls never touch (or quarantine) another run.
        if claims is not None:
            # A subject-scope detector can contain every run of a token subject. The subject is
            # only trustworthy now that the token has verified.
            if (reason := self.quarantine.reason(f"subject:{claims.sub}")) is not None:
                violations.append(
                    Violation(
                        R_QUARANTINED,
                        "critical",
                        0,
                        Decision.BLOCK,
                        f"subject {claims.sub!r} is quarantined: {reason}",
                    )
                )
                if enforce:
                    return self._finish(ctx, violations, now_dt, t0, subject=claims.sub)
            if claims.env != ctx.target_env:
                violations.append(
                    Violation(
                        R_ENV_PIVOT,
                        "critical",
                        1,
                        Decision.BLOCK,
                        f"{claims.env.value!r} credential used against {ctx.target_env.value!r}",
                        quarantine=True,
                    )
                )
            if ctx.tool_name not in claims.allowed_tools:
                violations.append(
                    Violation(
                        R_TOOL_NOT_PINNED,
                        "high",
                        3,
                        Decision.BLOCK,
                        f"tool {ctx.tool_name!r} is not in the token's pinned allowed_tools",
                        quarantine=True,
                    )
                )

            # [3] Off-hours policy adjustment (pure function of policy x clock).
            effective = self._off_hours.effective(now_dt)
            if effective.off_hours_reason is not None:
                violations.append(
                    Violation(
                        R_OFF_HOURS,
                        "low",
                        4,
                        Decision.ALLOW,
                        f"off-hours thresholds applied: {effective.off_hours_reason}",
                    )
                )

            # [4] Stateless HITL gates + sliding-window detectors (short critical section).
            gate_violations: list[Violation] = []
            # The gates are given no claims: whether a pending HITL requirement is satisfied is
            # decided below, by a per-transaction approval or the deprecated run-wide claim.
            gate = self._hitl.evaluate(ctx.tool_name, ctx.amount, ctx.currency, None, effective)
            if gate is not None:
                gate_violations.append(gate)
            new_ben = self._new_beneficiary.evaluate(
                ctx.tool_name,
                ctx.beneficiary,
                ctx.amount,
                ctx.currency,
                None,
                effective,
                ctx.beneficiaries,
            )
            if new_ben is not None:
                gate_violations.append(new_ben)

            # One critical section covers the cap check, step-up resolution, every window and the
            # cap record, so concurrent calls cannot both slip under a cap, and a call that is
            # refused or waiting for step-up is never counted. Verifying an approval inside it only
            # happens for calls that carry one.
            approval_notes: list[Violation] = []
            with self._state_lock:
                cap_violation = self._cap.check(
                    ctx.agent_run_id,
                    ctx.tool_name,
                    ctx.amount,
                    ctx.currency,
                    now,
                    effective,
                    subject=claims.sub,
                )
                if cap_violation is not None:
                    gate_violations.append(cap_violation)

                pending = [v for v in gate_violations if v.decision is Decision.HITL_REQUIRED]
                if pending:
                    cleared, approval_notes = self._resolve_step_up(ctx, claims, pending)
                    if cleared:
                        gate_violations = [
                            v for v in gate_violations if v.decision is not Decision.HITL_REQUIRED
                        ]
                has_hitl_rejection = any(
                    v.decision is Decision.HITL_REQUIRED for v in gate_violations
                )

                probe = self._micro.observe(
                    ctx.agent_run_id, ctx.amount, ctx.currency, now, effective
                )
                burst = self._velocity.observe(ctx.agent_run_id, ctx.tool_name, now, effective)
                structuring = (
                    None
                    if has_hitl_rejection
                    else self._structuring.observe(
                        ctx.agent_run_id,
                        ctx.tool_name,
                        ctx.amount,
                        ctx.currency,
                        now,
                        effective,
                        claims,
                        subject=claims.sub,
                        beneficiaries=payees_of(ctx),
                    )
                )
                sequence = self._sequence.observe(ctx.agent_run_id, ctx.tool_name, now)
                if not has_hitl_rejection and (
                    cap_violation is None or cap_violation not in gate_violations
                ):
                    self._cap.record(
                        ctx.agent_run_id,
                        ctx.tool_name,
                        ctx.amount,
                        ctx.currency,
                        now,
                        subject=claims.sub,
                    )
            violations.extend(v for v in (probe, burst, structuring, sequence) if v is not None)
            violations.extend(gate_violations)
            violations.extend(approval_notes)

        return self._finish(
            ctx, violations, now_dt, t0, subject=claims.sub if claims is not None else None
        )

    def _finish(
        self,
        ctx: ToolCallContext,
        violations: list[Violation],
        now_dt: datetime,
        t0: int,
        subject: str | None = None,
    ) -> Evaluation:
        decision = Decision.ALLOW
        for v in violations:
            if v.decision is Decision.BLOCK:
                decision = Decision.BLOCK
                break
            if v.decision is Decision.HITL_REQUIRED:
                decision = Decision.HITL_REQUIRED

        enforced = self.policy.mode is Mode.ENFORCE
        findings = [self._to_finding(ctx, v, now_dt, enforced) for v in violations]
        for f in findings:
            try:
                self.telemetry_sink.emit(f.model_copy())
            except Exception:
                self.telemetry_failures += 1
                _log.exception("telemetry sink emit failed for finding %s", f.finding_id)

        # Containment is recorded in BOTH modes (observe mode never consults it to block).
        if self.policy.quarantine_on_block:
            for v in violations:
                if not v.quarantine:
                    continue
                keys = [ctx.agent_run_id]
                if v.quarantine_subject and subject:
                    keys.append(f"subject:{subject}")
                for key in keys:
                    try:
                        self.quarantine.add(key, f"{v.rule_id}: {v.detail}", now_dt)
                    except Exception:
                        self.quarantine_failures += 1
                        _log.exception(
                            "quarantine journal write failed for %s (rule %s)", key, v.rule_id
                        )
        request: ApprovalRequest | None = None
        if decision is Decision.HITL_REQUIRED:
            pending = [
                v
                for v in violations
                if v.decision is Decision.HITL_REQUIRED and v.rule_id != R_APPROVAL_REJECTED
            ]
            request = build_request(
                ctx,
                tuple(v.rule_id for v in pending),
                tuple(v.detail for v in pending),
                now_dt,
            )
        return Evaluation(decision, findings, (time.perf_counter_ns() - t0) // 1000, request)

    @staticmethod
    def _to_finding(
        ctx: ToolCallContext, v: Violation, now_dt: datetime, enforced: bool
    ) -> M42Finding:
        return M42Finding(
            finding_id=str(uuid.uuid4()),
            rule_id=v.rule_id,
            severity=v.severity,  # type: ignore[arg-type]
            stage=v.stage,
            decision=v.decision,
            would_have_blocked=v.decision is not Decision.ALLOW,
            enforced=enforced,
            agent_run_id=ctx.agent_run_id,
            tool_name=ctx.tool_name,
            detail=v.detail,
            observed_at=now_dt.astimezone(UTC),
        )

    # ------------------------------------------------------------------------------
    # Actuation + audit
    # ------------------------------------------------------------------------------

    def _raise_for(self, evaluation: Evaluation) -> None:
        f = evaluation.primary_finding()
        if f is None or f.decision is Decision.ALLOW:
            return
        if f.decision is Decision.HITL_REQUIRED:
            exc_cls: type[ShieldError] = HITLRequiredError
        else:
            exc_cls = _EXCEPTION_FOR_RULE.get(f.rule_id, ShieldError)
        error = exc_cls(f"[{f.rule_id}] {f.detail}", f)
        error.approval_request = evaluation.approval_request
        raise error

    def _write_audit(
        self,
        ctx: ToolCallContext,
        evaluation: Evaluation,
        outcome: Literal["executed", "blocked", "tool_error"],
    ) -> AuditRecord | None:
        redactions = {"token": "sha256:" + hashlib.sha256(ctx.token.encode()).hexdigest()}
        if ctx.approval is not None:
            redactions["approval"] = "sha256:" + hashlib.sha256(ctx.approval.encode()).hexdigest()
        redacted = ctx.model_copy(update=redactions)
        body = {
            "ts": self._clock().astimezone(UTC).isoformat(),
            "mode": self.policy.mode.value,
            "context": redacted.model_dump(mode="json"),
            "decision": evaluation.decision.value,
            "findings": [f.model_dump(mode="json") for f in evaluation.findings],
            "latency_us": evaluation.latency_us,
            "tool_outcome": outcome,
        }
        try:
            return cast(AuditRecord, self.audit.append(body))
        except Exception:
            self.audit_failures += 1
            _log.exception("audit log write failed (decision %s)", evaluation.decision.value)
            return None

    # ------------------------------------------------------------------------------
    # Decorator
    # ------------------------------------------------------------------------------

    def guard(self, fn: F, *, ctx_arg: str = "ctx") -> F:
        """Wrap a sync or async tool. The caller must pass a ``ToolCallContext`` as ``ctx=``.

        ``ctx`` is forwarded to the tool only if the tool declares a parameter with that name.
        """
        forwards_ctx = ctx_arg in inspect.signature(fn).parameters

        def prepare(kwargs: dict[str, Any]) -> tuple[ToolCallContext, Evaluation]:
            raw = kwargs.get(ctx_arg) if forwards_ctx else kwargs.pop(ctx_arg, None)
            if not isinstance(raw, ToolCallContext):
                raise MissingContextError(
                    f"guarded tool {fn.__name__!r} must be called with "
                    f"{ctx_arg}=ToolCallContext(...)"
                )
            evaluation = self.evaluate(raw)
            if self.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW:
                self._write_audit(raw, evaluation, "blocked")
                self._raise_for(evaluation)
            return raw, evaluation

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx, evaluation = prepare(kwargs)
                try:
                    result = await fn(*args, **kwargs)
                except BaseException:
                    self._write_audit(ctx, evaluation, "tool_error")
                    raise
                self._write_audit(ctx, evaluation, "executed")
                return result

            return cast(F, async_wrapper)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx, evaluation = prepare(kwargs)
            try:
                result = fn(*args, **kwargs)
            except BaseException:
                self._write_audit(ctx, evaluation, "tool_error")
                raise
            self._write_audit(ctx, evaluation, "executed")
            return result

        return cast(F, sync_wrapper)

    def close(self) -> None:
        self.audit.close()


def redhand_guard(shield: Shield, *, ctx_arg: str = "ctx") -> Callable[[F], F]:
    """Decorator factory: ``@redhand_guard(shield)`` over a sync or async tool function."""

    def decorator(fn: F) -> F:
        return shield.guard(fn, ctx_arg=ctx_arg)

    return decorator
