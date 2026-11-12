"""End-to-end tests: the four CRAFTY FALCON stages, both modes, sync/async, concurrency, latency."""

from __future__ import annotations

import asyncio
import hashlib
import json
import statistics
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from redhand_fintech_shield import (
    AgentQuarantinedError,
    AgentTokenIssuer,
    Decision,
    Env,
    HashChainedAuditLog,
    HITLRequiredError,
    MicroTxProbeError,
    MissingContextError,
    Mode,
    PolicyConfig,
    PolicyLoadError,
    Shield,
    TokenInvalidError,
    TokenPivotError,
    ToolCallContext,
    ToolNotPinnedError,
    VelocityExceededError,
    redhand_guard,
)
from redhand_fintech_shield.detectors import R_ENV_PIVOT, R_MICRO_TX, R_OFF_HOURS, R_VELOCITY

from .conftest import WEEKEND_UTC, FakeClock

MakeCtx = Callable[..., ToolCallContext]
MakeShield = Callable[..., Shield]


@dataclass
class Tools:
    charge_card: Callable[..., str]
    settle_merchant: Callable[..., str]
    list_merchants: Callable[..., str]
    calls: list[str] = field(default_factory=list)


def build_tools(shield: Shield) -> Tools:
    calls: list[str] = []

    @redhand_guard(shield)
    def charge_card(amount: str, *, ctx: ToolCallContext) -> str:
        calls.append("charge_card")
        return f"charged {amount}"

    @redhand_guard(shield)
    def settle_merchant(*, ctx: ToolCallContext) -> str:
        calls.append("settle_merchant")
        return "settled"

    @redhand_guard(shield)
    def list_merchants(*, ctx: ToolCallContext) -> str:
        calls.append("list_merchants")
        return "merchants"

    return Tools(charge_card, settle_merchant, list_merchants, calls)


def audit_rows(shield: Shield) -> list[dict[str, Any]]:
    return [json.loads(x) for x in shield.audit.path.read_text().splitlines()]


# ------------------------------------------------------------------------------------
# Happy path
# ------------------------------------------------------------------------------------


def test_clean_call_executes_and_is_audited(shield: Shield, make_ctx: MakeCtx) -> None:
    tools = build_tools(shield)
    assert tools.list_merchants(ctx=make_ctx(tool="list_merchants")) == "merchants"
    (row,) = audit_rows(shield)
    assert row["decision"] == "allow" and row["tool_outcome"] == "executed"
    assert HashChainedAuditLog.verify_chain(shield.audit.path).ok


def test_ctx_is_forwarded_only_when_tool_declares_it(shield: Shield, make_ctx: MakeCtx) -> None:
    seen: dict[str, Any] = {}

    @shield.guard
    def no_ctx(x: int) -> int:
        return x + 1

    @shield.guard
    def with_ctx(x: int, ctx: ToolCallContext) -> int:
        seen["ctx"] = ctx
        return x + 1

    assert no_ctx(1, ctx=make_ctx(tool="charge_card")) == 2  # type: ignore[call-arg]
    c = make_ctx(tool="charge_card", run="run-2")
    assert with_ctx(1, ctx=c) == 2 and seen["ctx"] is c


def test_missing_context_fails_closed_and_tool_not_run(shield: Shield) -> None:
    tools = build_tools(shield)
    with pytest.raises(MissingContextError):
        tools.list_merchants()
    with pytest.raises(MissingContextError):
        tools.list_merchants(ctx="not a context")
    assert tools.calls == []


def test_raw_token_never_written_to_audit(shield: Shield, make_ctx: MakeCtx) -> None:
    ctx = make_ctx(tool="list_merchants")
    build_tools(shield).list_merchants(ctx=ctx)
    text = shield.audit.path.read_text()
    assert ctx.token not in text
    assert hashlib.sha256(ctx.token.encode()).hexdigest() in text


def test_tool_exception_is_audited_and_propagates(shield: Shield, make_ctx: MakeCtx) -> None:
    @shield.guard
    def boom(*, ctx: ToolCallContext) -> None:
        raise RuntimeError("downstream failure")

    with pytest.raises(RuntimeError):
        boom(ctx=make_ctx(tool="charge_card"))
    assert audit_rows(shield)[-1]["tool_outcome"] == "tool_error"


# ------------------------------------------------------------------------------------
# Stage 1: staging -> prod token pivot, plus token integrity
# ------------------------------------------------------------------------------------


def test_stage1_staging_token_cannot_call_prod(shield: Shield, make_ctx: MakeCtx) -> None:
    tools = build_tools(shield)
    ctx = make_ctx(tool="charge_card", env=Env.PROD, token_env=Env.STAGING, amount="100")
    with pytest.raises(TokenPivotError) as err:
        tools.charge_card("100", ctx=ctx)
    assert err.value.finding is not None and err.value.finding.rule_id == R_ENV_PIVOT
    assert tools.calls == []
    assert shield.quarantine.is_quarantined("run-1")
    assert audit_rows(shield)[-1]["tool_outcome"] == "blocked"


def test_stage1_same_env_token_is_fine(shield: Shield, make_ctx: MakeCtx) -> None:
    tools = build_tools(shield)
    tools.list_merchants(ctx=make_ctx(tool="list_merchants", env=Env.STAGING))
    assert tools.calls == ["list_merchants"]


@pytest.mark.parametrize("bad", ["", "garbage", "a.b.c"])
def test_invalid_token_blocked(shield: Shield, make_ctx: MakeCtx, bad: str) -> None:
    tools = build_tools(shield)
    with pytest.raises(TokenInvalidError):
        tools.list_merchants(ctx=make_ctx(tool="list_merchants", token=bad))
    assert tools.calls == []


def test_token_bound_to_other_run_is_rejected(shield: Shield, make_ctx: MakeCtx) -> None:
    stolen = make_ctx(run="victim-run", tool="list_merchants").token
    with pytest.raises(TokenInvalidError, match="different agent run"):
        build_tools(shield).list_merchants(
            ctx=make_ctx(run="attacker-run", tool="list_merchants", token=stolen)
        )


def test_unauthenticated_calls_cannot_quarantine_a_victim(
    shield: Shield, make_ctx: MakeCtx
) -> None:
    tools = build_tools(shield)
    for _ in range(50):
        with pytest.raises(TokenInvalidError):
            tools.charge_card(
                "1", ctx=make_ctx(run="victim", tool="charge_card", token="forged", amount="1")
            )
    assert not shield.quarantine.is_quarantined("victim")
    tools.list_merchants(ctx=make_ctx(run="victim", tool="list_merchants"))  # victim unaffected


def test_expired_token_blocked(shield: Shield, make_ctx: MakeCtx, clock: FakeClock) -> None:
    ctx = make_ctx(tool="list_merchants")
    clock.advance(901)
    with pytest.raises(TokenInvalidError, match="expired"):
        build_tools(shield).list_merchants(ctx=ctx)


# ------------------------------------------------------------------------------------
# Stage 2: micro-transaction probing and velocity
# ------------------------------------------------------------------------------------


def test_stage2_second_probe_in_60s_trips_breaker_and_quarantines(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    tools = build_tools(shield)
    assert tools.charge_card("0.50", ctx=make_ctx(tool="charge_card", amount="0.50"))
    clock.advance(5)
    with pytest.raises(MicroTxProbeError) as err:
        tools.charge_card("1.00", ctx=make_ctx(tool="charge_card", amount="1.00"))
    assert err.value.finding is not None and err.value.finding.rule_id == R_MICRO_TX
    assert tools.calls == ["charge_card"]  # the 2nd probe never reached the payment rail
    # Third attempt: agent is contained, even for a harmless call.
    with pytest.raises(AgentQuarantinedError):
        tools.list_merchants(ctx=make_ctx(tool="list_merchants"))


def test_stage2_probes_spaced_beyond_window_are_allowed(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    tools = build_tools(shield)
    tools.charge_card("1.00", ctx=make_ctx(tool="charge_card", amount="1.00"))
    clock.advance(61)
    tools.charge_card("1.00", ctx=make_ctx(tool="charge_card", amount="1.00"))
    assert len(tools.calls) == 2


def test_stage2_normal_sized_payments_never_trip(shield: Shield, make_ctx: MakeCtx) -> None:
    tools = build_tools(shield)
    for _ in range(10):
        tools.charge_card("250.00", ctx=make_ctx(tool="charge_card", amount="250.00"))
    assert len(tools.calls) == 10


def test_stage2_enumeration_burst_trips_velocity(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    tools = build_tools(shield)
    ctx = make_ctx(tool="list_merchants")
    for _ in range(20):
        tools.list_merchants(ctx=ctx)
    with pytest.raises(VelocityExceededError) as err:
        tools.list_merchants(ctx=ctx)
    assert err.value.finding is not None and err.value.finding.rule_id == R_VELOCITY
    assert shield.quarantine.is_quarantined("run-1")


# ------------------------------------------------------------------------------------
# Stage 3: tool pinning and HITL on settlement / disbursement
# ------------------------------------------------------------------------------------


def test_stage3_unpinned_tool_blocked(shield: Shield, make_ctx: MakeCtx) -> None:
    tools = build_tools(shield)
    ctx = make_ctx(tool="settle_merchant", allowed=("charge_card",), amount="10", hitl=True)
    with pytest.raises(ToolNotPinnedError):
        tools.settle_merchant(ctx=ctx)
    assert tools.calls == []


def test_stage3_high_value_settlement_needs_hitl(shield: Shield, make_ctx: MakeCtx) -> None:
    tools = build_tools(shield)
    with pytest.raises(HITLRequiredError):
        tools.settle_merchant(ctx=make_ctx(tool="settle_merchant", amount="25000"))
    assert not shield.quarantine.is_quarantined("run-1")  # a human can still step up
    tools.settle_merchant(ctx=make_ctx(tool="settle_merchant", amount="25000", hitl=True))
    assert tools.calls == ["settle_merchant"]


def test_stage3_amount_at_threshold_passes_without_hitl(shield: Shield, make_ctx: MakeCtx) -> None:
    build_tools(shield).settle_merchant(ctx=make_ctx(tool="settle_merchant", amount="10000"))


# ------------------------------------------------------------------------------------
# Stage 4: low-monitoring windows
# ------------------------------------------------------------------------------------


def test_stage4_weekend_requires_hitl_for_small_settlement(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    tools = build_tools(shield)
    tools.settle_merchant(ctx=make_ctx(tool="settle_merchant", amount="100"))  # weekday OK
    clock.wall = WEEKEND_UTC
    with pytest.raises(HITLRequiredError) as err:
        tools.settle_merchant(ctx=make_ctx(tool="settle_merchant", amount="100"))
    assert err.value.finding is not None and err.value.finding.stage == 4
    tools.settle_merchant(ctx=make_ctx(tool="settle_merchant", amount="100", hitl=True))


def test_stage4_weekend_probe_trips_on_first_micro_payment(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    clock.wall = WEEKEND_UTC
    with pytest.raises(MicroTxProbeError):
        build_tools(shield).charge_card("1.00", ctx=make_ctx(tool="charge_card", amount="1.00"))


def test_stage4_off_hours_finding_is_attached_to_audit(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    clock.wall = WEEKEND_UTC
    build_tools(shield).list_merchants(ctx=make_ctx(tool="list_merchants"))
    rules = [f["rule_id"] for f in audit_rows(shield)[-1]["findings"]]
    assert R_OFF_HOURS in rules


def test_caller_claimed_timestamp_cannot_dodge_off_hours(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    clock.wall = WEEKEND_UTC
    base = make_ctx(tool="settle_merchant", amount="100")
    spoofed = base.model_copy(
        update={"timestamp": clock.now().replace(day=11)}
    )  # claims a Wednesday
    with pytest.raises(HITLRequiredError):
        build_tools(shield).settle_merchant(ctx=spoofed)


# ------------------------------------------------------------------------------------
# enforce vs observe_only
# ------------------------------------------------------------------------------------


def test_observe_only_executes_but_records_would_have_blocked(
    make_shield: MakeShield, make_ctx: MakeCtx
) -> None:
    shield = make_shield(Mode.OBSERVE_ONLY)
    tools = build_tools(shield)
    ctx = make_ctx(tool="charge_card", env=Env.PROD, token_env=Env.STAGING, amount="100")
    assert tools.charge_card("100", ctx=ctx) == "charged 100"  # attack "succeeds" in observe mode
    row = audit_rows(shield)[-1]
    assert row["mode"] == "observe_only" and row["decision"] == "block"
    assert row["tool_outcome"] == "executed"
    pivot = next(f for f in row["findings"] if f["rule_id"] == R_ENV_PIVOT)
    assert pivot["would_have_blocked"] is True and pivot["enforced"] is False
    assert shield.quarantine.is_quarantined("run-1")  # recorded...
    tools.list_merchants(ctx=make_ctx(tool="list_merchants"))  # ...but never blocks
    assert any(
        f["rule_id"].endswith("agent_quarantined") for f in audit_rows(shield)[-1]["findings"]
    )


def test_modes_produce_identical_findings_for_the_same_calls(
    make_shield: MakeShield, make_ctx: MakeCtx, clock: FakeClock, tmp_path: Path
) -> None:
    def run(mode: Mode, sub: str) -> list[tuple[int, str, str]]:
        (tmp_path / sub).mkdir()
        shield = make_shield(
            mode,
            audit_path=tmp_path / sub / "a.jsonl",
            quarantine_journal_path=tmp_path / sub / "q.jsonl",
        )
        out: list[tuple[int, str, str]] = []
        for amount in ("0.50", "1.00"):
            ev = shield.evaluate(make_ctx(tool="charge_card", amount=amount))
            out += [(f.stage, f.rule_id, f.decision.value) for f in ev.findings]
        return out

    assert run(Mode.ENFORCE, "e") == run(Mode.OBSERVE_ONLY, "o")


def test_enforce_blocked_call_audited_exactly_once(shield: Shield, make_ctx: MakeCtx) -> None:
    with pytest.raises(TokenPivotError):
        build_tools(shield).charge_card(
            "1", ctx=make_ctx(tool="charge_card", token_env=Env.STAGING, amount="1")
        )
    assert len(audit_rows(shield)) == 1


# ------------------------------------------------------------------------------------
# Containment persistence, audit failure handling, construction
# ------------------------------------------------------------------------------------


def test_quarantine_survives_restart(
    make_shield: MakeShield, make_ctx: MakeCtx, shield: Shield, tmp_path: Path
) -> None:
    with pytest.raises(TokenPivotError):
        build_tools(shield).charge_card(
            "1", ctx=make_ctx(tool="charge_card", token_env=Env.STAGING, amount="1")
        )
    shield.close()
    reborn = make_shield(
        audit_path=tmp_path / "second.jsonl"
    )  # same journal path as policy fixture
    with pytest.raises(AgentQuarantinedError):
        build_tools(reborn).list_merchants(ctx=make_ctx(tool="list_merchants"))


def test_audit_write_failure_does_not_mask_block(shield: Shield, make_ctx: MakeCtx) -> None:
    shield.audit.close()  # subsequent appends raise ValueError internally
    with pytest.raises(TokenPivotError):
        build_tools(shield).charge_card(
            "1", ctx=make_ctx(tool="charge_card", token_env=Env.STAGING, amount="1")
        )
    assert shield.audit_failures == 1


def test_shield_without_verifier_or_key_path_is_refused(policy: PolicyConfig) -> None:
    with pytest.raises(PolicyLoadError):
        Shield(policy)


def test_shield_builds_verifier_from_policy_key_path(
    policy: PolicyConfig, keypair: Any, tmp_path: Path, clock: FakeClock
) -> None:
    from redhand_fintech_shield.crypto import public_key_to_pem

    key_path = tmp_path / "pub.pem"
    key_path.write_bytes(public_key_to_pem(keypair[1]))
    shield = Shield(
        policy.model_copy(update={"verifier_public_key_path": key_path}),
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    token = AgentTokenIssuer(keypair[0]).mint(
        subject="s",
        agent_run_id="r",
        env=Env.PROD,
        allowed_tools=["list_merchants"],
        now=clock.now(),
    )
    ctx = ToolCallContext(
        agent_run_id="r", tool_name="list_merchants", target_env=Env.PROD, token=token
    )
    assert shield.evaluate(ctx).decision is Decision.ALLOW


# ------------------------------------------------------------------------------------
# async
# ------------------------------------------------------------------------------------


def test_async_tool_guarded(shield: Shield, make_ctx: MakeCtx) -> None:
    @redhand_guard(shield)
    async def async_charge(amount: str, *, ctx: ToolCallContext) -> str:
        await asyncio.sleep(0)
        return f"async {amount}"

    async def scenario() -> None:
        assert (
            await async_charge("0.50", ctx=make_ctx(tool="charge_card", amount="0.50"))
            == "async 0.50"
        )
        with pytest.raises(MicroTxProbeError):
            await async_charge("1.00", ctx=make_ctx(tool="charge_card", amount="1.00"))

    asyncio.run(scenario())
    assert asyncio.iscoroutinefunction(async_charge)
    assert [r["tool_outcome"] for r in audit_rows(shield)] == ["executed", "blocked"]


# ------------------------------------------------------------------------------------
# Concurrency and latency
# ------------------------------------------------------------------------------------


def test_thread_safe_exact_velocity_accounting(make_shield: MakeShield, make_ctx: MakeCtx) -> None:
    shield = make_shield(Mode.OBSERVE_ONLY)  # observe: no early exit, every call hits the window
    ctx = make_ctx(tool="list_merchants")
    results: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        local = 0
        for _ in range(25):
            ev = shield.evaluate(ctx)
            local += sum(1 for f in ev.findings if f.rule_id == R_VELOCITY)
        with lock:
            results.append(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == 200 - 20  # frozen clock: exactly the calls beyond the limit trip


def test_concurrent_guarded_calls_keep_audit_chain_valid(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    tools = build_tools(shield)
    ctxs = [make_ctx(run=f"run-{i}", tool="list_merchants") for i in range(8)]

    def worker(c: ToolCallContext) -> None:
        for _ in range(15):
            tools.list_merchants(ctx=c)

    threads = [threading.Thread(target=worker, args=(c,)) for c in ctxs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    report = HashChainedAuditLog.verify_chain(shield.audit.path)
    assert report.ok and report.records_checked == 120


def test_latency_budget_under_2ms(shield: Shield, make_ctx: MakeCtx, clock: FakeClock) -> None:
    tools = build_tools(shield)
    ctx = make_ctx(tool="list_merchants")
    for _ in range(50):  # warm-up
        clock.advance(0.1)
        tools.list_merchants(ctx=ctx)

    decision_us: list[int] = []
    guarded_ms: list[float] = []
    for _ in range(1000):
        clock.advance(0.25)  # ~8 calls/s overall: below the velocity limit
        decision_us.append(shield.evaluate(ctx).latency_us)
        clock.advance(0.25)
        t0 = time.perf_counter()
        tools.list_merchants(ctx=ctx)  # full path: evaluate + tool + hash-chained audit write
        guarded_ms.append((time.perf_counter() - t0) * 1000)

    decision_p99 = statistics.quantiles(decision_us, n=100)[98] / 1000
    guarded_p99 = statistics.quantiles(guarded_ms, n=100)[98]
    assert decision_p99 < 2.0, f"decision core p99 {decision_p99:.3f} ms"
    assert guarded_p99 < 2.0, f"end-to-end p99 {guarded_p99:.3f} ms"
