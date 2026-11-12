from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from redhand_fintech_shield import Decision, Env, PolicyConfig, TokenClaims
from redhand_fintech_shield.detectors import (
    R_HITL,
    R_MICRO_TX,
    R_OFF_HOURS_HITL,
    R_VELOCITY,
    HighValueGate,
    KeyedSlidingWindow,
    MicroTxProbeDetector,
    OffHoursEvaluator,
    QuarantineRegistry,
    SlidingWindowCounter,
    VelocityDetector,
)

from .conftest import BUSINESS_HOURS_UTC, PRESET, WEEKEND_UTC

POLICY = PolicyConfig.from_yaml(PRESET)
NORMAL = OffHoursEvaluator(POLICY).effective(BUSINESS_HOURS_UTC)
WEEKEND = OffHoursEvaluator(POLICY).effective(WEEKEND_UTC)


def claims(*, hitl: bool = False) -> TokenClaims:
    return TokenClaims(
        iss="redhand",
        sub="s",
        agent_run_id="r",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=hitl,
        iat=0,
        exp=1,
        jti="j",
    )


# --- sliding window ---------------------------------------------------------------------


def test_window_counts_and_evicts() -> None:
    w = SlidingWindowCounter(60, maxlen=10)
    assert [w.hit(t) for t in (0, 10, 20)] == [1, 2, 3]
    assert w.hit(61) == 3  # t=0 evicted (<= cutoff 1), 10/20/61 remain
    assert w.hit(200) == 1


def test_window_boundary_is_exclusive_of_exactly_one_window_ago() -> None:
    w = SlidingWindowCounter(60, maxlen=10)
    w.hit(0)
    assert w.hit(60) == 1  # the event exactly 60s old has left the window
    w2 = SlidingWindowCounter(60, maxlen=10)
    w2.hit(0)
    assert w2.hit(59.999) == 2


def test_window_is_memory_bounded() -> None:
    w = SlidingWindowCounter(60, maxlen=3)
    for t in range(100):
        w.hit(t * 0.001)
    assert len(w) == 3


def test_keyed_window_sweeps_idle_keys() -> None:
    kw = KeyedSlidingWindow(1.0, maxlen=5, sweep_every=10, sweep_batch=1000)
    for i in range(50):
        kw.hit(f"idle-{i}", 0.0)
    assert len(kw) == 50
    for _ in range(10):
        kw.hit("live", 100.0)  # the 10th op triggers a sweep far in the future
    assert len(kw) == 1


# --- micro-tx ---------------------------------------------------------------------------


def probe(det: MicroTxProbeDetector, amt: str, cur: str | None, t: float, eff=NORMAL):  # type: ignore[no-untyped-def]
    return det.observe("run", Decimal(amt), cur, t, eff)


def test_second_probe_in_window_trips() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    assert probe(det, "0.50", "USD", 0) is None
    v = probe(det, "1.00", "USD", 1)
    assert v is not None and v.rule_id == R_MICRO_TX and v.decision is Decision.BLOCK
    assert v.quarantine


def test_probe_ceiling_is_inclusive_and_above_is_ignored() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    assert probe(det, "5.00", "USD", 0) is None
    assert probe(det, "5.00", "USD", 1) is not None
    det2 = MicroTxProbeDetector(POLICY.micro_tx)
    for t in range(10):
        assert probe(det2, "5.01", "USD", t) is None


def test_probes_outside_window_do_not_accumulate() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    assert probe(det, "1", "USD", 0) is None
    assert probe(det, "1", "USD", 61) is None


def test_probe_windows_are_per_agent_run() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    assert det.observe("a", Decimal("1"), "USD", 0, NORMAL) is None
    assert det.observe("b", Decimal("1"), "USD", 1, NORMAL) is None


@pytest.mark.parametrize(("cur", "ok_amt"), [("INR", "1"), ("MYR", "1")])
def test_advisory_inr_and_myr_one_unit_are_probes(cur: str, ok_amt: str) -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    assert probe(det, ok_amt, cur, 0) is None
    assert probe(det, ok_amt, cur, 1) is not None


def test_unknown_or_missing_currency_fails_closed_even_for_large_amounts() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    assert probe(det, "900000", "XYZ", 0) is None
    assert probe(det, "900000", "XYZ", 1) is not None
    det2 = MicroTxProbeDetector(POLICY.micro_tx)
    assert probe(det2, "5", None, 0) is None
    assert probe(det2, "5", None, 1) is not None


def test_no_amount_is_not_a_probe() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    for t in range(5):
        assert det.observe("run", None, None, t, NORMAL) is None


def test_off_hours_trips_on_first_probe() -> None:
    det = MicroTxProbeDetector(POLICY.micro_tx)
    v = probe(det, "1", "USD", 0, WEEKEND)
    assert v is not None and "weekend" in v.detail


# --- velocity ---------------------------------------------------------------------------


def test_velocity_trips_above_limit_per_tool() -> None:
    det = VelocityDetector(POLICY.velocity)
    for i in range(20):
        assert det.observe("r", "list_merchants", i * 0.001, NORMAL) is None
    v = det.observe("r", "list_merchants", 0.5, NORMAL)
    assert v is not None and v.rule_id == R_VELOCITY
    assert det.observe("r", "other_tool", 0.5, NORMAL) is None


def test_velocity_recovers_after_window() -> None:
    det = VelocityDetector(POLICY.velocity)
    for i in range(21):
        det.observe("r", "t", i * 0.001, NORMAL)
    assert det.observe("r", "t", 5.0, NORMAL) is None


def test_velocity_halved_off_hours() -> None:
    det = VelocityDetector(POLICY.velocity)
    results = [det.observe("r", "t", i * 0.001, WEEKEND) for i in range(11)]
    assert results[9] is None and results[10] is not None  # limit 10 instead of 20


# --- off-hours --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("when", "expected"),
    [
        (datetime(2026, 11, 11, 5, 30, tzinfo=UTC), None),  # Wed 11:00 IST
        (datetime(2026, 11, 11, 3, 29, tzinfo=UTC), "outside business hours"),  # 08:59 IST
        (datetime(2026, 11, 11, 3, 30, tzinfo=UTC), None),  # 09:00 IST boundary: open
        (datetime(2026, 11, 11, 12, 29, tzinfo=UTC), None),  # 17:59 IST
        (datetime(2026, 11, 11, 12, 30, tzinfo=UTC), "outside business hours"),  # 18:00 IST
        (datetime(2026, 11, 14, 5, 30, tzinfo=UTC), "weekend"),  # Saturday
        (datetime(2026, 11, 15, 5, 30, tzinfo=UTC), "weekend"),  # Sunday
        (datetime(2026, 12, 25, 5, 30, tzinfo=UTC), "public holiday"),  # Friday, Christmas
    ],
)
def test_off_hours_reason(when: datetime, expected: str | None) -> None:
    reason = OffHoursEvaluator(POLICY).reason(when)
    if expected is None:
        assert reason is None
    else:
        assert reason is not None and expected in reason


def test_local_date_not_utc_date_decides_weekend() -> None:
    # Fri 2026-11-13 20:00 UTC is already Sat 01:30 IST.
    assert "weekend" in (
        OffHoursEvaluator(POLICY).reason(datetime(2026, 11, 13, 20, 0, tzinfo=UTC)) or ""
    )


def test_off_hours_disabled() -> None:
    pol = POLICY.model_copy(
        update={"off_hours": POLICY.off_hours.model_copy(update={"enabled": False})}
    )
    assert OffHoursEvaluator(pol).reason(WEEKEND_UTC) is None


def test_tightened_thresholds_are_scaled() -> None:
    assert WEEKEND.hitl_thresholds["USD"] == Decimal("5000.0")
    assert WEEKEND.max_probes == 1 and WEEKEND.max_velocity_calls == 10
    assert NORMAL.max_probes == 2 and NORMAL.hitl_thresholds["USD"] == Decimal("10000")


# --- HITL gate --------------------------------------------------------------------------

GATE = HighValueGate(POLICY.hitl)


def test_hitl_threshold_is_strictly_greater_than() -> None:
    assert GATE.evaluate("settle_merchant", Decimal("10000"), "USD", claims(), NORMAL) is None
    v = GATE.evaluate("settle_merchant", Decimal("10000.01"), "USD", claims(), NORMAL)
    assert v is not None and v.rule_id == R_HITL and v.decision is Decision.HITL_REQUIRED


def test_step_up_claim_satisfies_gate() -> None:
    assert (
        GATE.evaluate("settle_merchant", Decimal("1000000"), "USD", claims(hitl=True), NORMAL)
        is None
    )


def test_unprotected_tool_never_gated() -> None:
    assert GATE.evaluate("charge_card", Decimal("1000000"), "USD", claims(), NORMAL) is None


def test_missing_amount_and_unknown_currency_fail_closed() -> None:
    assert GATE.evaluate("settle_merchant", None, None, claims(), NORMAL) is not None
    assert GATE.evaluate("settle_merchant", Decimal("1"), "XYZ", claims(), NORMAL) is not None
    assert GATE.evaluate("settle_merchant", Decimal("1"), "XYZ", None, NORMAL) is not None


def test_off_hours_mandatory_hitl_even_for_small_amounts() -> None:
    v = GATE.evaluate("settle_merchant", Decimal("1"), "USD", claims(), WEEKEND)
    assert v is not None and v.rule_id == R_OFF_HOURS_HITL and v.stage == 4
    assert GATE.evaluate("settle_merchant", Decimal("1"), "USD", claims(hitl=True), WEEKEND) is None


def test_off_hours_tightened_threshold_when_not_mandatory() -> None:
    pol = POLICY.model_copy(
        update={"off_hours": POLICY.off_hours.model_copy(update={"mandatory_hitl": False})}
    )
    eff = OffHoursEvaluator(pol).effective(WEEKEND_UTC)
    gate = HighValueGate(pol.hitl)
    assert gate.evaluate("settle_merchant", Decimal("4999"), "USD", claims(), eff) is None
    assert gate.evaluate("settle_merchant", Decimal("5001"), "USD", claims(), eff) is not None


# --- quarantine -------------------------------------------------------------------------


def test_quarantine_add_is_idempotent_and_journaled(tmp_path: Path) -> None:
    journal = tmp_path / "q.jsonl"
    q = QuarantineRegistry(journal)
    assert q.add("r1", "because") is True
    assert q.add("r1", "again") is False
    assert q.is_quarantined("r1") and not q.is_quarantined("r2")
    assert QuarantineRegistry(journal).snapshot() == {"r1": "because"}


def test_quarantine_journal_survives_torn_line(tmp_path: Path) -> None:
    journal = tmp_path / "q.jsonl"
    journal.write_text('{"agent_run_id":"r1","reason":"x"}\n{"agent_run_id":"r2","rea')
    assert QuarantineRegistry(journal).snapshot() == {"r1": "x"}
