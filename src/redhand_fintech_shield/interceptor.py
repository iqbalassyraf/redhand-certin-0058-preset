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

from .audit import HashChainedAuditLog
from .crypto import AgentTokenVerifier, load_public_key_pem, utcnow
from .detectors import (
    R_ENV_PIVOT,
    R_HITL,
    R_MICRO_TX,
    R_OFF_HOURS,
    R_OFF_HOURS_HITL,
    R_QUARANTINED,
    R_TOKEN_INVALID,
    R_TOOL_NOT_PINNED,
    R_VELOCITY,
    HighValueGate,
    MicroTxProbeDetector,
    OffHoursEvaluator,
    QuarantineRegistry,
    VelocityDetector,
    Violation,
)
from .exceptions import (
    AgentQuarantinedError,
    HITLRequiredError,
    MicroTxProbeError,
    MissingContextError,
    PolicyLoadError,
    ShieldError,
    TokenInvalidError,
    TokenPivotError,
    ToolNotPinnedError,
    VelocityExceededError,
)
from .models import (
    AuditRecord,
    Decision,
    M42Finding,
    Mode,
    PolicyConfig,
    TokenClaims,
    ToolCallContext,
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
    R_HITL: HITLRequiredError,
    R_OFF_HOURS_HITL: HITLRequiredError,
}


@dataclass(frozen=True, slots=True)
class Evaluation:
    decision: Decision
    findings: list[M42Finding]
    latency_us: int


class Shield:
    """Holds policy, detector state, quarantine set and audit log for one protected process."""

    def __init__(
        self,
        policy: PolicyConfig,
        verifier: AgentTokenVerifier | None = None,
        *,
        audit: HashChainedAuditLog | None = None,
        clock: Callable[[], datetime] = utcnow,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self._clock = clock
        self._monotonic = monotonic
        self._verifier = verifier or self._verifier_from_policy(policy, clock)
        self.audit = audit or HashChainedAuditLog(policy.audit_path, fsync=policy.audit_fsync)
        self.quarantine = QuarantineRegistry(policy.quarantine_journal_path)

        self._off_hours = OffHoursEvaluator(policy)
        self._micro = MicroTxProbeDetector(policy.micro_tx)
        self._velocity = VelocityDetector(policy.velocity)
        self._hitl = HighValueGate(policy.hitl)
        self._state_lock = threading.Lock()  # guards the sliding windows only
        self.audit_failures = 0

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

            # [4] Sliding-window detectors (short critical section) + stateless HITL gate.
            with self._state_lock:
                probe = self._micro.observe(
                    ctx.agent_run_id, ctx.amount, ctx.currency, now, effective
                )
                burst = self._velocity.observe(ctx.agent_run_id, ctx.tool_name, now, effective)
            violations.extend(v for v in (probe, burst) if v is not None)
            gate = self._hitl.evaluate(ctx.tool_name, ctx.amount, ctx.currency, claims, effective)
            if gate is not None:
                violations.append(gate)

        return self._finish(ctx, violations, now_dt, t0)

    def _finish(
        self, ctx: ToolCallContext, violations: list[Violation], now_dt: datetime, t0: int
    ) -> Evaluation:
        enforced = self.policy.mode is Mode.ENFORCE
        findings = [self._to_finding(ctx, v, now_dt, enforced) for v in violations]
        decision = Decision.ALLOW
        for f in findings:
            if f.decision is Decision.BLOCK:
                decision = Decision.BLOCK
                break
            if f.decision is Decision.HITL_REQUIRED:
                decision = Decision.HITL_REQUIRED

        # Containment is recorded in BOTH modes (observe mode never consults it to block).
        if self.policy.quarantine_on_block:
            for v in violations:
                if v.quarantine:
                    self.quarantine.add(ctx.agent_run_id, f"{v.rule_id}: {v.detail}", now_dt)
        return Evaluation(decision, findings, (time.perf_counter_ns() - t0) // 1000)

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
        for f in evaluation.findings:
            if f.decision is not Decision.ALLOW:
                exc_cls = _EXCEPTION_FOR_RULE.get(f.rule_id, ShieldError)
                raise exc_cls(f"[{f.rule_id}] {f.detail}", f)

    def _write_audit(
        self,
        ctx: ToolCallContext,
        evaluation: Evaluation,
        outcome: Literal["executed", "blocked", "tool_error"],
    ) -> AuditRecord | None:
        redacted = ctx.model_copy(
            update={"token": "sha256:" + hashlib.sha256(ctx.token.encode()).hexdigest()}
        )
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
            return self.audit.append(body)
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
