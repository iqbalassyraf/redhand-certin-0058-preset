"""Phase 3 Milestone 1 tests: Structuring, New-Beneficiary, and Sequence detectors."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from redhand_fintech_shield import (
    AgentQuarantinedError,
    AgentTokenIssuer,
    Decision,
    Env,
    HITLRequiredError,
    Mode,
    NewBeneficiaryError,
    PolicyConfig,
    SequenceViolationError,
    Shield,
    StructuringError,
    ToolCallContext,
    load_policy,
)
from redhand_fintech_shield.adapters._common import (
    extract_tool_call_context as adapter_extract_ctx,
)
from redhand_fintech_shield.adapters._common import (
    sanitize_arguments as adapter_sanitize_args,
)
from redhand_fintech_shield.adapters.generic import GenericToolRunner
from redhand_fintech_shield.detectors import (
    R_NEW_BENEFICIARY,
    R_SEQUENCE,
    R_STRUCTURING,
    NewBeneficiaryDetector,
    OffHoursEvaluator,
    SequenceRuleDetector,
    StructuringDetector,
)
from redhand_fintech_shield.gateway import (
    extract_tool_call_context as gw_extract_ctx,
)
from redhand_fintech_shield.gateway import (
    sanitize_arguments as gw_sanitize_args,
)
from redhand_fintech_shield.models import (
    HITLPolicy,
    NewBeneficiaryPolicy,
    SequencePolicy,
    StructuringPolicy,
)
from tests.conftest import BUSINESS_HOURS_UTC, WEEKEND_UTC, FakeClock

MakeCtx = Callable[..., ToolCallContext]


# --------------------------------------------------------------------------------------
# 1. Models & Preset Validation
# --------------------------------------------------------------------------------------


def test_phase3_policy_models_reject_floats_invalid_amounts_and_extra_keys() -> None:
    """Rationale: Financial thresholds must use exact Decimal strings/ints, never floats."""
    with pytest.raises(ValidationError, match="never float"):
        StructuringPolicy(thresholds={"USD": 10000.0})  # type: ignore[dict-item]

    with pytest.raises(ValidationError, match="never float"):
        NewBeneficiaryPolicy(thresholds={"USD": 1000.5})  # type: ignore[dict-item]

    with pytest.raises(ValidationError, match="at least one currency"):
        StructuringPolicy(thresholds={})

    with pytest.raises(ValidationError, match="finite, non-negative"):
        NewBeneficiaryPolicy(thresholds={"USD": Decimal("-1")})

    with pytest.raises(ValidationError):
        SequencePolicy(min_recon_calls=0)

    with pytest.raises(ValidationError):
        StructuringPolicy(unknown_key=True)  # type: ignore[call-arg]


def test_bundled_preset_loads_phase3_sections() -> None:
    """Rationale: Bundled CIAD-2026-0058 preset must include all three Phase 3 sections."""
    pol = load_policy()
    assert pol.structuring.enabled is True
    assert pol.structuring.thresholds["USD"] == Decimal("10000")
    assert pol.structuring.thresholds["INR"] == Decimal("900000")
    assert "settle_merchant" in pol.structuring.protected_tools
    assert "charge_card" not in pol.structuring.protected_tools
    assert pol.structuring.window_seconds == 300.0
    assert pol.structuring.min_tx_count == 2

    assert pol.new_beneficiary.enabled is True
    assert pol.new_beneficiary.thresholds["USD"] == Decimal("1000")
    assert pol.new_beneficiary.action == "hitl_required"

    assert pol.sequence.enabled is True
    assert "list_merchants" in pol.sequence.recon_tools
    assert "settle_merchant" in pol.sequence.payment_tools
    assert pol.sequence.min_recon_calls == 3
    assert pol.sequence.window_seconds == 30.0


def test_tool_call_context_beneficiary_validation(
    issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    """Rationale: beneficiary is optional (backward-compatible), but rejects empty strings."""
    tok = issuer.mint(
        subject="svc",
        agent_run_id="run-b",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        now=clock.now(),
    )
    ctx_none = ToolCallContext(
        agent_run_id="run-b", tool_name="settle_merchant", target_env=Env.PROD, token=tok
    )
    assert ctx_none.beneficiary is None

    ctx_val = ToolCallContext(
        agent_run_id="run-b",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token=tok,
        beneficiary="acct-999",
    )
    assert ctx_val.beneficiary == "acct-999"

    with pytest.raises(ValidationError):
        ToolCallContext(
            agent_run_id="run-b",
            tool_name="settle_merchant",
            target_env=Env.PROD,
            token=tok,
            beneficiary="",
        )


# --------------------------------------------------------------------------------------
# 2. StructuringDetector (CIAD-2026-0058.R2.structuring)
# --------------------------------------------------------------------------------------


def test_structuring_single_large_tx_does_not_trip() -> None:
    """Rationale: A single large tx must route to HITL rather than structuring (min_tx_count=2)."""
    pol = PolicyConfig()
    eff = OffHoursEvaluator(pol).effective(BUSINESS_HOURS_UTC)
    det = StructuringDetector(pol.structuring)

    v = det.observe("run-1", "settle_merchant", Decimal("25000"), "USD", 100.0, eff)
    assert v is None


def test_structuring_multiple_below_threshold_and_window_expiry() -> None:
    """Rationale: Cumulative sums <= threshold or spaced past window_seconds must be allowed."""
    pol = PolicyConfig(
        structuring=StructuringPolicy(
            protected_tools=frozenset({"settle_merchant"}),
            thresholds={"USD": Decimal("10000")},
            window_seconds=60.0,
            min_tx_count=2,
        )
    )
    eff = OffHoursEvaluator(pol).effective(BUSINESS_HOURS_UTC)
    det = StructuringDetector(pol.structuring)

    assert det.observe("run-1", "settle_merchant", Decimal("4000"), "USD", 10.0, eff) is None
    assert det.observe("run-1", "settle_merchant", Decimal("6000"), "USD", 20.0, eff) is None
    # Advance past window (10.0 and 20.0 both <= 90.0 - 60.0 = 30.0)
    assert det.observe("run-1", "settle_merchant", Decimal("8000"), "USD", 90.0, eff) is None


def test_structuring_trips_on_split_smurfing_and_quarantines(
    shield: Shield, make_ctx: MakeCtx
) -> None:
    """Rationale: Splitting $12,000 into two $6,000 settlements evades HITL and must block."""

    @shield.guard
    def settle_merchant(amount: str, ctx: ToolCallContext | None = None) -> str:
        return f"settled {amount}"

    assert (
        settle_merchant(
            "6000", ctx=make_ctx(run="run-smurf", tool="settle_merchant", amount="6000")
        )
        == "settled 6000"
    )
    with pytest.raises(StructuringError) as exc_info:
        settle_merchant(
            "6000", ctx=make_ctx(run="run-smurf", tool="settle_merchant", amount="6000")
        )
    assert exc_info.value.finding is not None
    assert exc_info.value.finding.rule_id == R_STRUCTURING
    assert shield.quarantine.is_quarantined("run-smurf")

    with pytest.raises(AgentQuarantinedError):
        settle_merchant("100", ctx=make_ctx(run="run-smurf", tool="settle_merchant", amount="100"))


def test_structuring_off_hours_tightening_and_fail_closed_currency() -> None:
    """Rationale: Off-hours halves structuring threshold; unknown currency fails closed."""
    pol = PolicyConfig()
    eff_off = OffHoursEvaluator(pol).effective(WEEKEND_UTC)
    det = StructuringDetector(pol.structuring)

    # Normal threshold is 10000 USD; off-hours tighten_factor=0.5 -> 5000 USD.
    assert det.observe("run-off", "settle_merchant", Decimal("3000"), "USD", 10.0, eff_off) is None
    v = det.observe("run-off", "settle_merchant", Decimal("3000"), "USD", 11.0, eff_off)
    assert v is not None
    assert v.rule_id == R_STRUCTURING
    assert v.decision is Decision.BLOCK
    assert v.quarantine is True
    assert "tightened for" in v.detail

    # Unknown currency fails closed once min_tx_count reached
    assert det.observe("run-unk", "settle_merchant", Decimal("100"), "ZZZ", 10.0, eff_off) is None
    v_unk = det.observe("run-unk", "settle_merchant", Decimal("100"), "ZZZ", 11.0, eff_off)
    assert v_unk is not None
    assert v_unk.rule_id == R_STRUCTURING
    assert "fail-closed" in v_unk.detail


def test_structuring_isolation_disabled_and_capacity_sweep() -> None:
    """Rationale: Separate runs/currencies are isolated; bounded deque & sweep stay accurate."""
    pol = PolicyConfig()
    eff = OffHoursEvaluator(pol).effective(BUSINESS_HOURS_UTC)

    disabled = StructuringDetector(StructuringPolicy(enabled=False))
    assert disabled.observe("r1", "settle_merchant", Decimal("99999"), "USD", 1.0, eff) is None
    assert disabled.observe("r1", "settle_merchant", None, "USD", 1.0, eff) is None

    # Bounded capacity eviction + sweep
    s_pol = StructuringPolicy(
        thresholds={"USD": Decimal("100")}, window_seconds=10.0, min_tx_count=2
    )
    eff_small = OffHoursEvaluator(PolicyConfig(structuring=s_pol)).effective(BUSINESS_HOURS_UTC)
    det = StructuringDetector(
        s_pol,
        max_entries=2,
        sweep_every=2,
        sweep_batch=4,
    )
    assert det.observe("r1", "settle_merchant", Decimal("30"), "USD", 1.0, eff_small) is None
    assert det.observe("r2", "settle_merchant", Decimal("30"), "EUR", 2.0, eff_small) is None
    # r1 USD has 30 + 40 = 70 (<= 100)
    assert det.observe("r1", "settle_merchant", Decimal("40"), "USD", 3.0, eff_small) is None
    # 3rd entry within 10s hits max_entries=2 capacity -> fail-closed Violation
    v = det.observe("r1", "settle_merchant", Decimal("50"), "USD", 4.0, eff_small)
    assert v is not None and v.rule_id == R_STRUCTURING and v.quarantine is True
    # Advance far in time so sweep runs and cleans idle keys
    assert det.observe("r3", "settle_merchant", Decimal("10"), "USD", 100.0, eff_small) is None


# --------------------------------------------------------------------------------------
# 3. NewBeneficiaryDetector (CIAD-2026-0058.R3.new_beneficiary_high_value)
# --------------------------------------------------------------------------------------


def test_new_beneficiary_positive_and_negative_cases() -> None:
    """Rationale: Unseen beneficiaries above threshold require HITL (or block); known pass."""
    pol = PolicyConfig(
        new_beneficiary=NewBeneficiaryPolicy(
            thresholds={"USD": Decimal("1000")},
            known_beneficiaries=frozenset({"trusted-vendor"}),
            action="hitl_required",
        )
    )
    eff = OffHoursEvaluator(pol).effective(BUSINESS_HOURS_UTC)
    eff_off = OffHoursEvaluator(pol).effective(WEEKEND_UTC)
    det = NewBeneficiaryDetector(
        pol.new_beneficiary, protected_tools=frozenset({"settle_merchant"})
    )

    # Beneficiary omitted -> pass
    assert det.evaluate("settle_merchant", None, Decimal("5000"), "USD", None, eff) is None
    # Non-protected tool -> pass
    assert det.evaluate("charge_card", "new-acct", Decimal("5000"), "USD", None, eff) is None
    # Known beneficiary -> pass even above threshold
    assert (
        det.evaluate("settle_merchant", "trusted-vendor", Decimal("5000"), "USD", None, eff) is None
    )
    # Unknown beneficiary at or below threshold -> pass
    assert det.evaluate("settle_merchant", "new-acct", Decimal("1000"), "USD", None, eff) is None

    # Unknown beneficiary above threshold -> HITL_REQUIRED
    v = det.evaluate("settle_merchant", "new-acct", Decimal("1500"), "USD", None, eff)
    assert v is not None
    assert v.rule_id == R_NEW_BENEFICIARY
    assert v.decision is Decision.HITL_REQUIRED

    # Off-hours tightening halves threshold (1000 -> 500), so 600 triggers
    v_off = det.evaluate("settle_merchant", "new-acct", Decimal("600"), "USD", None, eff_off)
    assert v_off is not None
    assert v_off.rule_id == R_NEW_BENEFICIARY
    assert "tightened for" in v_off.detail

    # Fail-closed on missing amount or unknown currency
    v_no_amt = det.evaluate("settle_merchant", "new-acct", None, "USD", None, eff)
    assert v_no_amt is not None and "without an amount" in v_no_amt.detail
    v_unk = det.evaluate("settle_merchant", "new-acct", Decimal("10"), "ZZZ", None, eff)
    assert v_unk is not None and "fail-closed" in v_unk.detail


def test_new_beneficiary_block_action_and_shield_integration(
    make_shield: Callable[..., Shield],
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    """Rationale: action='block' raises NewBeneficiaryError; 'hitl_required' raises HITL."""
    # 1. action="hitl_required" -> HITLRequiredError, then allowed with hitl_step_up=True
    sh_hitl = make_shield()

    @sh_hitl.guard
    def settle_merchant(amount: str, ctx: ToolCallContext | None = None) -> str:
        return f"settled {amount}"

    tok_no = issuer.mint(
        subject="svc",
        agent_run_id="run-nb-1",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=clock.now(),
    )
    tok_yes = issuer.mint(
        subject="svc",
        agent_run_id="run-nb-1",
        env=Env.PROD,
        allowed_tools=("settle_merchant", "initiate_disbursement"),
        hitl_step_up=True,
        now=clock.now(),
    )

    with pytest.raises(HITLRequiredError):
        settle_merchant(
            "2000",
            ctx=ToolCallContext(
                agent_run_id="run-nb-1",
                tool_name="settle_merchant",
                target_env=Env.PROD,
                token=tok_no,
                amount=Decimal("2000"),
                currency="USD",
                beneficiary="mule-acct-1",
            ),
        )

    assert (
        settle_merchant(
            "2000",
            ctx=ToolCallContext(
                agent_run_id="run-nb-1",
                tool_name="settle_merchant",
                target_env=Env.PROD,
                token=tok_yes,
                amount=Decimal("2000"),
                currency="USD",
                beneficiary="mule-acct-1",
            ),
        )
        == "settled 2000"
    )

    # 2. action="block" -> NewBeneficiaryError even with hitl_step_up=True
    sh_block = make_shield(
        new_beneficiary=NewBeneficiaryPolicy(
            thresholds={"USD": Decimal("1000")},
            action="block",
        )
    )

    @sh_block.guard
    def initiate_disbursement(amount: str, ctx: ToolCallContext | None = None) -> str:
        return f"disbursed {amount}"

    with pytest.raises(NewBeneficiaryError) as exc_info:
        initiate_disbursement(
            "2000",
            ctx=ToolCallContext(
                agent_run_id="run-nb-1",
                tool_name="initiate_disbursement",
                target_env=Env.PROD,
                token=tok_yes,
                amount=Decimal("2000"),
                currency="USD",
                beneficiary="mule-acct-2",
            ),
        )
    assert exc_info.value.finding is not None
    assert exc_info.value.finding.rule_id == R_NEW_BENEFICIARY


# --------------------------------------------------------------------------------------
# 4. SequenceRuleDetector (CIAD-2026-0058.R2.recon_to_payment_sequence)
# --------------------------------------------------------------------------------------


def test_sequence_detector_unit_and_window_expiry() -> None:
    """Rationale: Recon burst < min_recon_calls or expired window must allow payment."""
    pol = SequencePolicy(
        recon_tools=frozenset({"list_merchants", "get_account"}),
        payment_tools=frozenset({"settle_merchant"}),
        min_recon_calls=3,
        window_seconds=30.0,
    )
    det = SequenceRuleDetector(pol)

    # Disabled detector is a no-op
    assert (
        SequenceRuleDetector(SequencePolicy(enabled=False)).observe("r0", "settle_merchant", 1.0)
        is None
    )

    # 2 recon calls (< 3) -> payment allowed
    assert det.observe("run-a", "list_merchants", 10.0) is None
    assert det.observe("run-a", "get_account", 11.0) is None
    assert det.observe("run-a", "settle_merchant", 12.0) is None

    # 3rd recon call on run-a, but payment on run-b -> allowed (run isolation)
    assert det.observe("run-a", "list_merchants", 13.0) is None
    assert det.observe("run-b", "settle_merchant", 14.0) is None

    # Wait past window_seconds (13.0 + 35.0 -> all 3 recon stamps expired) -> allowed
    assert det.observe("run-a", "settle_merchant", 45.0) is None


def test_sequence_detector_trips_and_quarantines_in_shield(
    shield: Shield, make_ctx: MakeCtx, clock: FakeClock
) -> None:
    """Rationale: >= 3 recon calls followed by payment within 30s blocks and quarantines."""

    @shield.guard
    def list_merchants(ctx: ToolCallContext | None = None) -> list[str]:
        return ["m1"]

    @shield.guard
    def settle_merchant(amount: str, ctx: ToolCallContext | None = None) -> str:
        return f"settled {amount}"

    for _ in range(3):
        clock.advance(1.0)
        list_merchants(ctx=make_ctx(run="run-seq", tool="list_merchants"))

    clock.advance(1.0)
    with pytest.raises(SequenceViolationError) as exc_info:
        settle_merchant("500", ctx=make_ctx(run="run-seq", tool="settle_merchant", amount="500"))
    assert exc_info.value.finding is not None
    assert exc_info.value.finding.rule_id == R_SEQUENCE
    assert shield.quarantine.is_quarantined("run-seq")


# --------------------------------------------------------------------------------------
# 5. Adapter / Gateway beneficiary extraction & Mode Parity
# --------------------------------------------------------------------------------------


def test_adapter_and_gateway_extract_beneficiary_and_preserve_in_sanitize(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    """Rationale: Adapters & gateway extract beneficiary without stripping it from tool args."""
    tok = issuer.mint(
        subject="svc",
        agent_run_id="run-ext",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        now=clock.now(),
    )

    for extract_fn, sanitize_fn in (
        (adapter_extract_ctx, adapter_sanitize_args),
        (gw_extract_ctx, gw_sanitize_args),
    ):
        args: dict[str, Any] = {
            "amount": "2500.00",
            "currency": "USD",
            "beneficiary": "  ext-acct-42  ",
            "token": tok,
        }
        ctx = extract_fn("settle_merchant", args)
        assert ctx.beneficiary == "ext-acct-42"
        sanitized = sanitize_fn(args)
        assert sanitized["beneficiary"] == "  ext-acct-42  "
        assert "token" not in sanitized

        # Whitespace-only beneficiary normalizes to None
        ctx_empty = extract_fn(
            "settle_merchant",
            {"amount": "100", "currency": "USD", "beneficiary": "   ", "_meta": {"token": tok}},
        )
        assert ctx_empty.beneficiary is None

    # End-to-end GenericToolRunner blocks unseen high-value beneficiary
    runner = GenericToolRunner(shield, raise_on_block=True)
    runner.register_tool("settle_merchant", lambda **kw: "ok")
    with pytest.raises(HITLRequiredError):
        runner.run(
            "settle_merchant",
            {
                "amount": "2500.00",
                "currency": "USD",
                "beneficiary": "unseen-vendor-99",
                "token": tok,
            },
        )


def test_mode_parity_enforce_vs_observe_only(
    make_shield: Callable[..., Shield], make_ctx: MakeCtx, clock: FakeClock
) -> None:
    """Rationale: ENFORCE and OBSERVE_ONLY must emit identical M42Findings for Phase 3 rules."""
    sh_enf = make_shield(mode=Mode.ENFORCE)
    sh_obs = make_shield(mode=Mode.OBSERVE_ONLY)

    # Structuring parity
    c1 = make_ctx(run="run-p1", tool="settle_merchant", amount="6000")
    c2 = make_ctx(run="run-p1", tool="settle_merchant", amount="6000")
    assert sh_enf.evaluate(c1).decision is Decision.ALLOW
    assert sh_obs.evaluate(c1).decision is Decision.ALLOW

    ev_enf = sh_enf.evaluate(c2)
    ev_obs = sh_obs.evaluate(c2)
    assert ev_enf.decision is Decision.BLOCK
    assert ev_obs.decision is Decision.BLOCK
    assert [f.rule_id for f in ev_enf.findings] == [R_STRUCTURING]
    assert [f.rule_id for f in ev_obs.findings] == [R_STRUCTURING]
    assert ev_enf.findings[0].enforced is True
    assert ev_obs.findings[0].enforced is False
    assert sh_obs.quarantine.is_quarantined("run-p1")

    # Sequence parity
    for _ in range(3):
        clock.advance(1.0)
        # A different subject: structuring above (run-p1) now contains its whole subject.
        rc = make_ctx(run="run-p2", subject="svc-p2", tool="list_merchants")
        sh_enf.evaluate(rc)
        sh_obs.evaluate(rc)
    clock.advance(1.0)
    pc = make_ctx(run="run-p2", subject="svc-p2", tool="settle_merchant", amount="100")
    seq_enf = sh_enf.evaluate(pc)
    seq_obs = sh_obs.evaluate(pc)
    assert [f.rule_id for f in seq_enf.findings] == [R_SEQUENCE]
    assert [f.rule_id for f in seq_obs.findings] == [R_SEQUENCE]


def test_structuring_not_bypassed_by_hitl_step_up_and_hitl_rejection_does_not_pollute_window(
    make_shield: Callable[..., Shield],
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    """Rationale: hitl_step_up=True must not bypass structuring; HITL rejections stay uncounted."""
    sh = make_shield(
        hitl=HITLPolicy(
            thresholds={"USD": Decimal("5000")},
            protected_tools=frozenset({"settle_merchant"}),
        ),
        structuring=StructuringPolicy(
            thresholds={"USD": Decimal("10000")},
            window_seconds=300.0,
            min_tx_count=2,
            protected_tools=frozenset({"settle_merchant"}),
        ),
    )

    @sh.guard
    def settle_merchant(amount: str, ctx: ToolCallContext | None = None) -> str:
        return f"settled {amount}"

    tok_no = issuer.mint(
        subject="svc",
        agent_run_id="run-hitl-struct",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=BUSINESS_HOURS_UTC,
    )
    tok_yes = issuer.mint(
        subject="svc",
        agent_run_id="run-hitl-struct",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=True,
        now=BUSINESS_HOURS_UTC,
    )

    # 1. Unexecuted HITL-rejected call must NOT pollute _WindowSum
    with pytest.raises(HITLRequiredError):
        settle_merchant(
            "6000",
            ctx=ToolCallContext(
                agent_run_id="run-hitl-struct",
                tool_name="settle_merchant",
                target_env=Env.PROD,
                token=tok_no,
                amount=Decimal("6000"),
                currency="USD",
            ),
        )

    # 2. Retry with hitl_step_up=True succeeds (only 1 executed tx of 6000 <= 10000)
    clock.advance(1.0)
    assert (
        settle_merchant(
            "6000",
            ctx=ToolCallContext(
                agent_run_id="run-hitl-struct",
                tool_name="settle_merchant",
                target_env=Env.PROD,
                token=tok_yes,
                amount=Decimal("6000"),
                currency="USD",
            ),
        )
        == "settled 6000"
    )

    # 3. Second executed tx with hitl_step_up=True (6000 + 6000 = 12000 > 10000) MUST block
    clock.advance(1.0)
    with pytest.raises(StructuringError):
        settle_merchant(
            "6000",
            ctx=ToolCallContext(
                agent_run_id="run-hitl-struct",
                tool_name="settle_merchant",
                target_env=Env.PROD,
                token=tok_yes,
                amount=Decimal("6000"),
                currency="USD",
            ),
        )
    assert sh.quarantine.is_quarantined("run-hitl-struct")


def test_structuring_fail_closed_on_missing_currency_and_window_saturation() -> None:
    """Rationale: Missing currency and _WindowSum capacity saturation must both fail closed."""
    pol = PolicyConfig(
        structuring=StructuringPolicy(
            thresholds={"USD": Decimal("10000")},
            window_seconds=300.0,
            min_tx_count=2,
            protected_tools=frozenset({"settle_merchant"}),
        )
    )
    eff = OffHoursEvaluator(pol).effective(BUSINESS_HOURS_UTC)

    # 1. currency=None fails closed once min_tx_count is reached
    det_curr = StructuringDetector(pol.structuring)
    assert det_curr.observe("r-none", "settle_merchant", Decimal("10"), None, 10.0, eff) is None
    v_none = det_curr.observe("r-none", "settle_merchant", Decimal("10"), None, 11.0, eff)
    assert v_none is not None
    assert v_none.rule_id == R_STRUCTURING
    assert v_none.decision is Decision.BLOCK
    assert v_none.quarantine is True
    assert "fail-closed" in v_none.detail

    # 2. High-volume small-tx > 1024 entries does not plateau at 1024 (default max_entries=16384)
    det_high = StructuringDetector(pol.structuring)
    blocked = False
    for i in range(2000):
        v = det_high.observe(
            "r-high", "settle_merchant", Decimal("5.01"), "USD", 100.0 + i * 0.01, eff
        )
        if v is not None:
            blocked = True
            assert v.rule_id == R_STRUCTURING
            assert v.decision is Decision.BLOCK
            break
    assert blocked, "2000 x $5.01 = $10,020 must trip StructuringDetector without plateauing"

    # 3. Capacity saturation fails closed even when total <= threshold
    det_sat = StructuringDetector(pol.structuring, max_entries=4)
    for i in range(4):
        assert (
            det_sat.observe("r-sat", "settle_merchant", Decimal("1.00"), "USD", 10.0 + i, eff)
            is None
        )
    v_sat = det_sat.observe("r-sat", "settle_merchant", Decimal("1.00"), "USD", 14.0, eff)
    assert v_sat is not None
    assert v_sat.rule_id == R_STRUCTURING
    assert v_sat.decision is Decision.BLOCK
    assert v_sat.quarantine is True
    assert "reached capacity" in v_sat.detail


def test_new_beneficiary_disabled_returns_none() -> None:
    """Rationale: NewBeneficiaryDetector(enabled=False) must be a no-op."""
    pol = PolicyConfig(
        new_beneficiary=NewBeneficiaryPolicy(
            enabled=False,
            thresholds={"USD": Decimal("100")},
            action="block",
        )
    )
    eff = OffHoursEvaluator(pol).effective(BUSINESS_HOURS_UTC)
    det = NewBeneficiaryDetector(
        pol.new_beneficiary, protected_tools=frozenset({"settle_merchant"})
    )
    assert det.evaluate("settle_merchant", "acct-new", Decimal("50000"), "USD", None, eff) is None
    assert det.evaluate("settle_merchant", "acct-new", None, None, None, eff) is None


def test_high_value_hitl_plus_new_beneficiary_block_raises_new_beneficiary_error(
    make_shield: Callable[..., Shield],
    issuer: AgentTokenIssuer,
) -> None:
    """Rationale: When HITL_REQUIRED and BLOCK both fire, BLOCK takes precedence everywhere."""
    sh = make_shield(
        hitl=HITLPolicy(
            thresholds={"USD": Decimal("10000")},
            protected_tools=frozenset({"settle_merchant"}),
        ),
        new_beneficiary=NewBeneficiaryPolicy(
            thresholds={"USD": Decimal("1000")},
            action="block",
        ),
    )

    @sh.guard
    def settle_merchant(amount: str, ctx: ToolCallContext | None = None) -> str:
        return f"settled {amount}"

    tok = issuer.mint(
        subject="svc",
        agent_run_id="run-precedence",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=BUSINESS_HOURS_UTC,
    )
    ctx = ToolCallContext(
        agent_run_id="run-precedence",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token=tok,
        amount=Decimal("15000"),
        currency="USD",
        beneficiary="acct-new",
    )

    ev = sh.evaluate(ctx)
    assert ev.decision is Decision.BLOCK
    primary = ev.primary_finding()
    assert primary is not None
    assert primary.rule_id == R_NEW_BENEFICIARY
    assert primary.decision is Decision.BLOCK

    with pytest.raises(NewBeneficiaryError):
        settle_merchant("15000", ctx=ctx)

    runner = GenericToolRunner(sh, raise_on_block=False)
    runner.register_tool("settle_merchant", lambda **kw: "ok")
    payload = runner.run(
        "settle_merchant",
        {
            "amount": "15000",
            "currency": "USD",
            "beneficiary": "acct-new",
            "token": tok,
        },
    )
    assert payload["rule_id"] == R_NEW_BENEFICIARY
    assert payload["decision"] == "block"
