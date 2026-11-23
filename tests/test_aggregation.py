"""Phase 3 Milestone 4 tests: harder aggregation.

Rationale: each M1 detector had a way around it. A new run id started a fresh structuring window;
a different payee spelling looked like a different payee; rotating tools never reached a per-tool
velocity limit; a different currency split the total; and nothing watched slow draining under every
window. Each test below is one of those bypasses, shown failing to evade the detector, next to the
benign traffic that must still pass.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from redhand_fintech_shield import (
    AgentQuarantinedError,
    AgentTokenIssuer,
    ApprovalIssuer,
    ApprovalVerifier,
    CumulativeCapError,
    Decision,
    Env,
    HITLRequiredError,
    Mode,
    PolicyConfig,
    Shield,
    ToolCallContext,
)
from redhand_fintech_shield.context import extract_tool_call_context
from redhand_fintech_shield.detectors import (
    R_APPROVAL_ACCEPTED,
    R_CUMULATIVE_CAP,
    R_QUARANTINED,
    R_STRUCTURING,
    R_VELOCITY,
    CumulativeCapDetector,
    NewBeneficiaryDetector,
    OffHoursEvaluator,
    StructuringDetector,
    VelocityDetector,
)
from redhand_fintech_shield.models import (
    AggregationPolicy,
    CumulativeCapPolicy,
    NewBeneficiaryPolicy,
    StructuringPolicy,
    VelocityPolicy,
)
from redhand_fintech_shield.normalize import canonical_beneficiary
from tests.conftest import BUSINESS_HOURS_UTC, PRESET, WEEKEND_UTC, FakeClock

pytestmark = pytest.mark.usefixtures("window_backend")

TOOL = "settle_merchant"


def eff(cfg: PolicyConfig, when: Any = BUSINESS_HOURS_UTC) -> Any:
    return OffHoursEvaluator(cfg).effective(when)


def agg(**rates: str) -> AggregationPolicy:
    return AggregationPolicy(base_currency="USD", rates={k: Decimal(v) for k, v in rates.items()})


# --------------------------------------------------------------------------------------
# A. Beneficiary normaliser
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("A@Bank", "a@bank"),
        ("  Alice@OkHDFC  ", "alice@okhdfc"),
        ("Ａ＠Ｂａｎｋ", "a@bank"),  # noqa: RUF001  # full-width (NFKC)
        ("GB82 WEST 1234 5698 7654 32", "GB82WEST12345698765432"),
        ("gb82-west-1234-5698-7654-32", "GB82WEST12345698765432"),
        ("hdfc0001234 : 1234567890", "HDFC0001234:1234567890"),
        ("HDFC0001234/1234567890", "HDFC0001234:1234567890"),
        ("Acme​  Ltd\t", "Acme Ltd"),  # zero-width and odd whitespace
        ("Mixed-Case-ID", "Mixed-Case-ID"),  # generic ids keep their case
        ("AC12ABCDEFGHIJK", "AC12ABCDEFGHIJK"),  # IBAN-shaped but checksum fails: left alone
        ("", ""),
        ("​‍", ""),
    ],
)
def test_canonical_beneficiary(raw: str, expected: str) -> None:
    assert canonical_beneficiary(raw) == expected


def test_generic_ids_that_differ_only_by_case_stay_distinct() -> None:
    assert canonical_beneficiary("Vendor-A") != canonical_beneficiary("vendor-a")


def test_known_beneficiaries_are_stored_canonically() -> None:
    pol = NewBeneficiaryPolicy(
        known_beneficiaries=frozenset({"Alice@UPI", "gb82 west 1234 5698 7654 32", " "})
    )
    assert pol.known_beneficiaries == frozenset({"alice@upi", "GB82WEST12345698765432"})


def test_known_payee_in_another_spelling_is_still_known() -> None:
    cfg = PolicyConfig.from_yaml(PRESET)
    nb = NewBeneficiaryPolicy(
        known_beneficiaries=frozenset({"alice@upi"}), thresholds={"USD": Decimal("1")}
    )
    det = NewBeneficiaryDetector(nb)
    args = ("settle_merchant", "ALICE@UPI", Decimal("500"), "USD", None, eff(cfg))
    assert det.evaluate(*args) is None  # hand-built context, raw spelling
    assert det.evaluate("settle_merchant", "bob@upi", Decimal("500"), "USD", None, eff(cfg))


def test_extraction_canonicalises_payees() -> None:
    ctx = extract_tool_call_context(
        "settle_merchant", {"amount": "1", "currency": "USD", "beneficiary": " Alice@UPI "}
    )
    assert ctx.beneficiary == "alice@upi"
    assert extract_tool_call_context("t", {"amount": "1", "beneficiary": "​ "}).beneficiary is None


# --------------------------------------------------------------------------------------
# B. All-tools velocity
# --------------------------------------------------------------------------------------


def _velocity(**kw: Any) -> tuple[VelocityDetector, Any, Any]:
    pol = VelocityPolicy(max_calls=20, max_total_calls=30, **kw)
    cfg = PolicyConfig(velocity=pol)
    return VelocityDetector(pol), eff(cfg), eff(cfg, WEEKEND_UTC)


def test_rotating_tools_cannot_stay_under_the_per_tool_limit() -> None:
    det, normal, _ = _velocity()
    hits = [
        det.observe("run", f"tool_{i % 10}", i * 0.001, normal)  # 4 calls on each of 10 tools
        for i in range(40)
    ]
    assert all(v is None for v in hits[:30])
    tripped = hits[30]
    assert tripped is not None and tripped.rule_id == R_VELOCITY and tripped.quarantine
    assert "across all tools" in tripped.detail and "tool rotation" in tripped.detail


def test_total_velocity_is_per_run_and_expires() -> None:
    det, normal, _ = _velocity()
    for i in range(30):
        assert det.observe("run-a", f"t{i % 5}", i * 0.001, normal) is None
    assert det.observe("run-b", "t0", 0.05, normal) is None  # another run is unaffected
    assert det.observe("run-a", "t0", 5.0, normal) is None  # a second later the window is empty


def test_total_velocity_is_tightened_off_hours_and_off_by_default() -> None:
    det, _, weekend = _velocity()
    results = [det.observe("run", f"t{i % 10}", i * 0.001, weekend) for i in range(20)]
    assert results[14] is None and results[15] is not None  # floor(30 * 0.5) = 15
    assert results[15] is not None and "tightened for weekend" in results[15].detail

    off = VelocityDetector(VelocityPolicy(max_calls=20))
    cfg = PolicyConfig()
    assert all(off.observe("run", f"t{i}", i * 0.001, eff(cfg)) is None for i in range(100))


def test_per_tool_limit_still_reported_first() -> None:
    det, normal, _ = _velocity()
    seen = [det.observe("run", "same", i * 0.001, normal) for i in range(25)]
    v = next(x for x in seen if x is not None)
    assert "called more than 20 times" in v.detail


# --------------------------------------------------------------------------------------
# C. Structuring scopes
# --------------------------------------------------------------------------------------


def _structuring(scopes: set[str], **kw: Any) -> tuple[StructuringDetector, Any]:
    aggregation = kw.pop("aggregation", None)
    pol = StructuringPolicy(
        thresholds={"USD": Decimal("10000"), "INR": Decimal("900000")},
        scopes=frozenset(scopes),  # type: ignore[arg-type]
        **kw,
    )
    return StructuringDetector(pol, aggregation=aggregation), eff(PolicyConfig(structuring=pol))


def test_default_scope_is_the_run_only() -> None:
    det, e = _structuring({"run"})
    assert det.observe("run-a", TOOL, Decimal("6000"), "USD", 1.0, e, subject="svc") is None
    assert det.observe("run-b", TOOL, Decimal("6000"), "USD", 2.0, e, subject="svc") is None


def test_new_run_id_does_not_reset_the_subject_window() -> None:
    det, e = _structuring({"run", "subject"})
    assert det.observe("run-a", TOOL, Decimal("6000"), "USD", 1.0, e, subject="svc") is None
    v = det.observe("run-b", TOOL, Decimal("6000"), "USD", 2.0, e, subject="svc")
    assert v is not None and v.rule_id == R_STRUCTURING
    assert v.quarantine and v.quarantine_subject
    assert "subject 'svc', across runs" in v.detail
    # a different subject is a different window
    assert det.observe("run-c", TOOL, Decimal("6000"), "USD", 3.0, e, subject="other") is None


def test_run_scope_violation_does_not_contain_the_whole_subject() -> None:
    det, e = _structuring({"run", "subject"})
    assert det.observe("run-a", TOOL, Decimal("6000"), "USD", 1.0, e, subject="svc") is None
    v = det.observe("run-a", TOOL, Decimal("6000"), "USD", 2.0, e, subject="svc")
    assert v is not None and v.quarantine and v.quarantine_subject  # subject window also tripped


def test_same_payee_across_runs_and_subjects_is_aggregated_after_canonicalising() -> None:
    det, e = _structuring({"run", "beneficiary"})
    one = det.observe("run-a", TOOL, Decimal("6000"), "USD", 1.0, e, beneficiaries=("Mule@Bank",))
    assert one is None
    v = det.observe(
        "run-b", TOOL, Decimal("6000"), "USD", 2.0, e, subject="s2", beneficiaries=("mule@BANK",)
    )
    assert v is not None and "beneficiary 'mule@bank', across runs" in v.detail
    assert not v.quarantine_subject
    other = det.observe("run-c", TOOL, Decimal("6000"), "USD", 3.0, e, beneficiaries=("bob@bank",))
    assert other is None


def test_multi_payee_calls_are_not_attributed_to_one_payee() -> None:
    det, e = _structuring({"run", "beneficiary"})
    for i, run in enumerate(("run-a", "run-b", "run-c")):
        got = det.observe(
            run, TOOL, Decimal("6000"), "USD", float(i), e, beneficiaries=("p1", "p2")
        )
        assert got is None


def test_tracker_fails_closed_when_full_then_recovers_after_the_window() -> None:
    det, e = _structuring({"run", "beneficiary"}, max_keys=2, window_seconds=300.0)
    assert det.observe("r1", TOOL, Decimal("1"), "USD", 0.0, e, beneficiaries=("p1",)) is None
    v = det.observe("r2", TOOL, Decimal("1"), "USD", 0.5, e, beneficiaries=("p2",))
    assert v is not None and "tracker is full" in v.detail and v.quarantine
    # still inside the window: still full, and repeated calls do not purge again within a second
    assert det.observe("r3", TOOL, Decimal("1"), "USD", 0.6, e, beneficiaries=("p3",)) is not None
    # after the window the old keys are purged and new traffic is accepted
    assert det.observe("r4", TOOL, Decimal("1"), "USD", 400.0, e, beneficiaries=("p4",)) is None


def test_cross_currency_splitting_is_aggregated_in_the_base_currency() -> None:
    det, e = _structuring({"run"}, aggregation=agg(INR="0.0111"))
    assert det.observe("r", TOOL, Decimal("6000"), "USD", 1.0, e) is None
    v = det.observe("r", TOOL, Decimal("540541"), "INR", 2.0, e)  # about 6,000 USD
    assert v is not None
    assert "converted to USD from INR" in v.detail
    # the same two payments with no aggregation never meet
    plain, e2 = _structuring({"run"})
    assert plain.observe("r", TOOL, Decimal("6000"), "USD", 1.0, e2) is None
    assert plain.observe("r", TOOL, Decimal("540541"), "INR", 2.0, e2) is None


def test_unconvertible_currency_falls_back_to_its_own_window_and_fails_closed() -> None:
    det, e = _structuring({"run"}, aggregation=agg(INR="0.0111"))
    assert det.observe("r", TOOL, Decimal("10"), "EUR", 1.0, e) is None
    v = det.observe("r", TOOL, Decimal("10"), "EUR", 2.0, e)
    assert v is not None and "no configured structuring threshold" in v.detail


# --------------------------------------------------------------------------------------
# D. Cumulative caps (detector level)
# --------------------------------------------------------------------------------------


def _cap(**kw: Any) -> tuple[CumulativeCapDetector, Any, PolicyConfig]:
    params: dict[str, Any] = {
        "enabled": True,
        "protected_tools": frozenset({TOOL}),
        "per_run": {"USD": Decimal("5000")},
        "per_subject": {"USD": Decimal("8000")},
    }
    params.update(kw)
    aggregation = params.pop("aggregation", None)
    pol = CumulativeCapPolicy(**params)
    cfg = PolicyConfig(cumulative_cap=pol)
    return CumulativeCapDetector(pol, aggregation=aggregation), eff(cfg), cfg


def test_cap_counts_only_recorded_payments() -> None:
    det, e, _ = _cap()
    assert det.check("r", TOOL, Decimal("3000"), "USD", 0.0, e, subject="s") is None
    det.record("r", TOOL, Decimal("3000"), "USD", 0.0, subject="s")
    v = det.check("r", TOOL, Decimal("3000"), "USD", 1.0, e, subject="s")
    assert v is not None and v.rule_id == R_CUMULATIVE_CAP
    assert v.decision is Decision.HITL_REQUIRED and not v.quarantine
    assert "run total would reach 6000 USD" in v.detail
    # the refused payment was never recorded, so a smaller one still fits
    assert det.check("r", TOOL, Decimal("2000"), "USD", 2.0, e, subject="s") is None


def test_slow_drain_across_runs_hits_the_subject_cap() -> None:
    det, e, _ = _cap()
    for i, run in enumerate(("r1", "r2")):
        assert det.check(run, TOOL, Decimal("4000"), "USD", float(i), e, subject="s") is None
        det.record(run, TOOL, Decimal("4000"), "USD", float(i), subject="s")
    v = det.check("r3", TOOL, Decimal("1"), "USD", 3.0, e, subject="s")
    assert v is not None and "subject 's', across runs" in v.detail
    assert det.check("r3", TOOL, Decimal("1"), "USD", 3.0, e, subject="other") is None


def test_cap_window_rolls() -> None:
    det, e, _ = _cap()
    det.record("r", TOOL, Decimal("5000"), "USD", 0.0, subject="s")
    assert det.check("r", TOOL, Decimal("1"), "USD", 100.0, e, subject="s") is not None
    assert det.check("r", TOOL, Decimal("1"), "USD", 86_401.0, e, subject="s") is None


def test_block_action_quarantines_the_run_and_the_subject() -> None:
    det, e, _ = _cap(action="block")
    det.record("r", TOOL, Decimal("5000"), "USD", 0.0, subject="s")
    run_hit = det.check("r", TOOL, Decimal("1"), "USD", 1.0, e, subject="s")
    assert run_hit is not None and run_hit.decision is Decision.BLOCK and run_hit.quarantine
    det.record("r2", TOOL, Decimal("3000"), "USD", 1.0, subject="s")
    sub_hit = det.check("r2", TOOL, Decimal("1"), "USD", 2.0, e, subject="s")
    assert sub_hit is not None and sub_hit.quarantine_subject


def test_cap_is_tightened_off_hours() -> None:
    det, _, cfg = _cap()
    weekend = eff(cfg, WEEKEND_UTC)
    det.record("r", TOOL, Decimal("2000"), "USD", 0.0, subject="s")
    v = det.check("r", TOOL, Decimal("600"), "USD", 1.0, weekend, subject="s")  # 2600 > 2500
    assert v is not None and "tightened for weekend" in v.detail


def test_cap_skips_what_it_does_not_cover() -> None:
    det, e, _ = _cap()
    assert det.check("r", "charge_card", Decimal("99999"), "USD", 0.0, e) is None  # unprotected
    assert det.check("r", TOOL, None, "USD", 0.0, e) is None  # no amount
    det.record("r", "charge_card", Decimal("99999"), "USD", 0.0)  # not recorded either
    det.record("r", TOOL, None, "USD", 0.0)
    assert det.check("r", TOOL, Decimal("5000"), "USD", 1.0, e) is None
    off = CumulativeCapDetector(CumulativeCapPolicy())
    assert off.check("r", TOOL, Decimal("99999"), "USD", 0.0, e) is None


def test_cap_fails_closed_on_unknown_currency_capacity_and_full_tracker() -> None:
    det, e, _ = _cap()
    v = det.check("r", TOOL, Decimal("1"), "EUR", 0.0, e, subject="s")
    assert v is not None and "no configured run cap" in v.detail
    assert det.check("r", TOOL, Decimal("1"), None, 0.0, e, subject="s") is not None

    small = CumulativeCapPolicy(enabled=True, per_run={"USD": Decimal("1000000")})
    det2 = CumulativeCapDetector(small, max_entries=2)
    e2 = eff(PolicyConfig(cumulative_cap=small))
    for t in (0.0, 1.0):
        det2.record("r", TOOL, Decimal("1"), "USD", t)
    v2 = det2.check("r", TOOL, Decimal("1"), "USD", 2.0, e2)
    assert v2 is not None and "reached capacity" in v2.detail

    tiny = CumulativeCapPolicy(enabled=True, per_run={"USD": Decimal("100")}, max_keys=1)
    det3 = CumulativeCapDetector(tiny)
    e3 = eff(PolicyConfig(cumulative_cap=tiny))
    det3.record("r1", TOOL, Decimal("1"), "USD", 0.0)
    v3 = det3.check("r2", TOOL, Decimal("1"), "USD", 1.0, e3)
    assert v3 is not None and "tracker is full" in v3.detail


def test_cap_aggregates_currencies_when_aggregation_is_on() -> None:
    det, e, _ = _cap(aggregation=agg(INR="0.0111"))
    det.record("r", TOOL, Decimal("360000"), "INR", 0.0, subject="s")  # about 4,000 USD
    v = det.check("r", TOOL, Decimal("1500"), "USD", 1.0, e, subject="s")
    assert v is not None and "5496" in v.detail  # 3,996 USD of INR + 1,500 USD


# --------------------------------------------------------------------------------------
# Policy validation
# --------------------------------------------------------------------------------------


def test_new_policy_models_reject_bad_values() -> None:
    with pytest.raises(ValidationError):
        VelocityPolicy(max_total_calls=0)
    with pytest.raises(ValidationError, match="at least one scope"):
        StructuringPolicy(scopes=frozenset())
    with pytest.raises(ValidationError, match="no per_run or per_subject"):
        CumulativeCapPolicy(enabled=True)
    with pytest.raises(ValidationError, match="non-negative"):
        CumulativeCapPolicy(per_run={"USD": Decimal("-1")})
    with pytest.raises(ValidationError, match="never float"):
        CumulativeCapPolicy(per_run={"USD": 1.5})  # type: ignore[dict-item]
    with pytest.raises(ValidationError, match="never float"):
        AggregationPolicy(base_currency="USD", rates={"INR": 0.0111})  # type: ignore[dict-item]
    with pytest.raises(ValidationError, match="positive"):
        AggregationPolicy(base_currency="USD", rates={"INR": Decimal("0")})
    with pytest.raises(ValidationError, match=r"needs aggregation\.base_currency"):
        AggregationPolicy(rates={"INR": Decimal("1")})
    with pytest.raises(ValidationError, match="must not have a rate"):
        AggregationPolicy(base_currency="USD", rates={"USD": Decimal("1")})


def test_aggregation_to_base_conversion_rules() -> None:
    a = agg(INR="0.0111")
    assert a.to_base(Decimal("100"), "USD") == (Decimal("100"), "USD")
    assert a.to_base(Decimal("1000"), "INR") == (Decimal("11.1000"), "USD")
    assert a.to_base(Decimal("1"), "EUR") is None
    assert a.to_base(Decimal("1"), None) is None
    assert AggregationPolicy().to_base(Decimal("1"), "USD") is None
    huge = agg(INR="1E+999999")
    assert huge.to_base(Decimal("1E+999999"), "INR") is None  # overflow is not convertible


def test_aggregation_needs_base_thresholds_in_the_policy() -> None:
    base = PolicyConfig.from_yaml(PRESET).model_dump()
    with pytest.raises(ValidationError, match=r"structuring\.thresholds has no EUR"):
        PolicyConfig.model_validate({**base, "aggregation": {"base_currency": "EUR"}})
    capped = {"enabled": True, "per_run": {"USD": "1"}}
    with pytest.raises(ValidationError, match=r"cumulative_cap\.per_run has no EUR"):
        PolicyConfig.model_validate(
            {
                **base,
                "structuring": {**base["structuring"], "thresholds": {"EUR": "1"}},
                "aggregation": {"base_currency": "EUR"},
                "cumulative_cap": capped,
            }
        )


def test_shipped_preset_turns_the_new_protections_on() -> None:
    cfg = PolicyConfig.from_yaml(PRESET)
    assert cfg.velocity.max_total_calls is not None
    assert cfg.structuring.scopes == {"run", "subject", "beneficiary"}
    assert cfg.aggregation.base_currency == "USD"
    assert cfg.cumulative_cap.enabled and cfg.cumulative_cap.action == "hitl_required"
    assert cfg.cumulative_cap.protected_tools <= cfg.protected_tools


# --------------------------------------------------------------------------------------
# End to end through the Shield
# --------------------------------------------------------------------------------------


@pytest.fixture
def mint(issuer: AgentTokenIssuer, clock: FakeClock) -> Callable[..., str]:
    def _mint(run: str, sub: str = "svc", hitl: bool = False) -> str:
        return issuer.mint(
            subject=sub,
            agent_run_id=run,
            env=Env.PROD,
            allowed_tools=(TOOL, "list_merchants", "get_account", "charge_card"),
            hitl_step_up=hitl,
            now=clock.now(),
        )

    return _mint


def pay(
    token: str,
    run: str,
    amount: str = "6000",
    *,
    currency: str = "USD",
    beneficiary: str | None = None,
    tool: str = TOOL,
) -> ToolCallContext:
    return ToolCallContext(
        agent_run_id=run,
        tool_name=tool,
        target_env=Env.PROD,
        token=token,
        amount=Decimal(amount),
        currency=currency,
        beneficiary=beneficiary,
    )


def test_subject_containment_blocks_a_fresh_run_of_the_same_subject(
    make_shield: Callable[..., Shield], policy: PolicyConfig, mint: Callable[..., str]
) -> None:
    sh = make_shield(
        structuring=policy.structuring.model_copy(update={"scopes": frozenset({"run", "subject"})})
    )
    assert sh.evaluate(pay(mint("run-a"), "run-a")).decision is Decision.ALLOW
    tripped = sh.evaluate(pay(mint("run-b"), "run-b"))
    assert tripped.decision is Decision.BLOCK
    assert any(f.rule_id == R_STRUCTURING for f in tripped.findings)
    assert sh.quarantine.is_quarantined("subject:svc")
    assert sh.quarantine.is_quarantined("run-b")

    later = sh.evaluate(pay(mint("run-c"), "run-c", "1"))  # brand-new run, same subject
    assert later.decision is Decision.BLOCK
    assert any(f.rule_id == R_QUARANTINED and "subject 'svc'" in f.detail for f in later.findings)
    assert sh.evaluate(pay(mint("run-d", "someone-else"), "run-d", "1")).decision is Decision.ALLOW


def test_subject_containment_in_observe_mode_records_but_does_not_block(
    make_shield: Callable[..., Shield], policy: PolicyConfig, mint: Callable[..., str]
) -> None:
    sh = make_shield(
        mode=Mode.OBSERVE_ONLY,
        structuring=policy.structuring.model_copy(update={"scopes": frozenset({"run", "subject"})}),
    )
    sh.evaluate(pay(mint("run-a"), "run-a"))
    sh.evaluate(pay(mint("run-b"), "run-b"))
    later = sh.evaluate(pay(mint("run-c"), "run-c", "1"))
    assert any(f.rule_id == R_QUARANTINED and not f.enforced for f in later.findings)


def test_rotating_tools_trip_the_all_tools_limit_through_the_shield(
    make_shield: Callable[..., Shield], policy: PolicyConfig, mint: Callable[..., str]
) -> None:
    sh = make_shield(
        velocity=policy.velocity.model_copy(update={"max_calls": 20, "max_total_calls": 12}),
        sequence=policy.sequence.model_copy(update={"enabled": False}),
    )
    token = mint("run-v")
    tools = ("list_merchants", "get_account", "charge_card")
    results = [sh.evaluate(pay(token, "run-v", "100", tool=tools[i % 3])) for i in range(14)]
    assert all(r.decision is Decision.ALLOW for r in results[:12])
    assert results[12].decision is Decision.BLOCK
    assert any(f.rule_id == R_VELOCITY for f in results[12].findings)


@pytest.fixture
def cap_policy(policy: PolicyConfig) -> Callable[..., dict[str, Any]]:
    def _updates(action: str = "hitl_required", **extra: Any) -> dict[str, Any]:
        return {
            "structuring": policy.structuring.model_copy(update={"enabled": False}),
            "cumulative_cap": CumulativeCapPolicy(
                enabled=True,
                protected_tools=frozenset({TOOL}),
                per_run={"USD": Decimal("10000")},
                per_subject={"USD": Decimal("15000")},
                action=action,  # type: ignore[arg-type]
            ),
            **extra,
        }

    return _updates


def test_refused_payment_is_not_counted_toward_the_cap(
    make_shield: Callable[..., Shield], cap_policy: Callable[..., dict[str, Any]], mint: Any
) -> None:
    sh = make_shield(**cap_policy())
    token = mint("run-c")
    assert sh.evaluate(pay(token, "run-c", "6000")).decision is Decision.ALLOW
    refused = sh.evaluate(pay(token, "run-c", "6000"))  # would reach 12,000
    assert refused.decision is Decision.HITL_REQUIRED
    assert refused.approval_request is not None
    assert R_CUMULATIVE_CAP in refused.approval_request.reasons
    assert (
        sh.evaluate(pay(token, "run-c", "3000")).decision is Decision.ALLOW
    )  # 9,000: refused one not counted


def test_cap_decorator_raises_the_right_exception_for_each_action(
    make_shield: Callable[..., Shield], cap_policy: Callable[..., dict[str, Any]], mint: Any
) -> None:
    def tool(**kw: Any) -> str:
        return "paid"

    soft = make_shield(**cap_policy())
    guarded = soft.guard(tool)
    guarded(ctx=pay(mint("run-s"), "run-s", "6000"))
    with pytest.raises(HITLRequiredError):
        guarded(ctx=pay(mint("run-s"), "run-s", "6000"))

    hard = make_shield(**cap_policy(action="block"))
    guarded = hard.guard(tool)
    guarded(ctx=pay(mint("run-h"), "run-h", "6000"))
    with pytest.raises(CumulativeCapError):
        guarded(ctx=pay(mint("run-h"), "run-h", "6000"))
    with pytest.raises(AgentQuarantinedError):
        guarded(ctx=pay(mint("run-h"), "run-h", "1"))


def test_approved_over_cap_payment_goes_through_and_is_then_counted(
    policy: PolicyConfig,
    verifier: Any,
    clock: FakeClock,
    issuer: AgentTokenIssuer,
    cap_policy: Callable[..., dict[str, Any]],
) -> None:
    approver_key, approver_pub = AgentTokenIssuer.generate_keypair()
    pol = policy.model_copy(update=cap_policy())
    sh = Shield(
        pol,
        verifier,
        approval_verifier=ApprovalVerifier(approver_pub, clock=clock.now),
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    token = issuer.mint(
        subject="svc", agent_run_id="run-a", env=Env.PROD, allowed_tools=(TOOL,), now=clock.now()
    )

    def call(amount: str, approval: str | None = None) -> ToolCallContext:
        args: dict[str, Any] = {"amount": amount, "currency": "USD", "token": token}
        if approval:
            args["approval"] = approval
        args["agent_run_id"] = "run-a"
        return extract_tool_call_context(TOOL, args, bindings=sh.policy.tool_bindings)

    assert sh.evaluate(call("6000")).decision is Decision.ALLOW
    asked = sh.evaluate(call("6000"))
    assert asked.decision is Decision.HITL_REQUIRED and asked.approval_request is not None
    grant = ApprovalIssuer(approver_key).grant(
        asked.approval_request, approver="alice", now=clock.now()
    )
    approved = sh.evaluate(call("6000", grant))
    assert approved.decision is Decision.ALLOW
    assert R_APPROVAL_ACCEPTED in {f.rule_id for f in approved.findings}
    # the approved 6,000 now counts: 12,000 used, so even 1 more needs step-up
    assert sh.evaluate(call("1")).decision is Decision.HITL_REQUIRED


def test_concurrent_callers_cannot_all_slip_under_the_cap(
    make_shield: Callable[..., Shield], cap_policy: Callable[..., dict[str, Any]], mint: Any
) -> None:
    sh = make_shield(**cap_policy())
    token = mint("run-t")
    contexts = [pay(token, "run-t", "2000") for _ in range(10)]
    decisions: list[Decision] = []
    barrier = threading.Barrier(len(contexts))

    def worker(ctx: ToolCallContext) -> None:
        barrier.wait()
        decisions.append(sh.evaluate(ctx).decision)

    threads = [threading.Thread(target=worker, args=(c,)) for c in contexts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert decisions.count(Decision.ALLOW) == 5  # 5 x 2,000 = the 10,000 run cap, no more
    assert decisions.count(Decision.HITL_REQUIRED) == 5


def test_cap_findings_are_identical_in_observe_only_mode(
    make_shield: Callable[..., Shield], cap_policy: Callable[..., dict[str, Any]], mint: Any
) -> None:
    enforce = make_shield(**cap_policy())
    observe = make_shield(mode=Mode.OBSERVE_ONLY, **cap_policy())
    token = mint("run-o")
    for sh in (enforce, observe):
        sh.evaluate(pay(token, "run-o", "6000"))
    a = enforce.evaluate(pay(token, "run-o", "6000"))
    b = observe.evaluate(pay(token, "run-o", "6000"))
    assert [f.rule_id for f in a.findings] == [f.rule_id for f in b.findings]
    assert a.findings[0].enforced is True and b.findings[0].enforced is False


def test_cross_currency_cap_through_the_shield(
    make_shield: Callable[..., Shield], cap_policy: Callable[..., dict[str, Any]], mint: Any
) -> None:
    sh = make_shield(**cap_policy(aggregation=agg(INR="0.0111")))
    token = mint("run-x")
    assert sh.evaluate(pay(token, "run-x", "540541", currency="INR")).decision is Decision.ALLOW
    over = sh.evaluate(pay(token, "run-x", "5000", currency="USD"))  # ~6,000 + 5,000 > 10,000
    assert over.decision is Decision.HITL_REQUIRED
