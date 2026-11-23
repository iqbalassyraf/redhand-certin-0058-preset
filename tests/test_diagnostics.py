"""Phase 4: configuration diagnostics and holiday-calendar coverage.

Rationale: the preset ships fixed-date holidays only, and a calendar that silently runs out turns
off-hours tightening into a no-op on exactly the days it matters. The shield warns at startup and
`doctor` reports, and every warning is a pure function of policy and time so it can be tested.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from redhand_fintech_shield import Mode, PolicyConfig, RuleOverride, Shield
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.detectors import R_STRUCTURING
from redhand_fintech_shield.diagnostics import holiday_years_missing, policy_warnings
from redhand_fintech_shield.models import (
    Exemption,
    ExemptionMatch,
    OffHoursPolicy,
    TokenKeyConfig,
)
from tests.conftest import PRESET

NOW = datetime(2026, 11, 23, 8, 0, tzinfo=UTC)


def codes(policy: PolicyConfig, now: datetime = NOW) -> set[str]:
    return {w.code for w in policy_warnings(policy, now)}


def preset() -> PolicyConfig:
    return PolicyConfig.from_yaml(PRESET)


# --------------------------------------------------------------------------------------
# Holiday coverage
# --------------------------------------------------------------------------------------


def test_the_preset_covers_this_year_and_next_and_through_2028() -> None:
    years = {d.year for d in preset().off_hours.holidays}
    assert {2026, 2027, 2028} <= years
    assert holiday_years_missing(preset(), NOW) == []
    assert not codes(preset()) & {"holidays-none", "holidays-missing-year"}


@pytest.mark.parametrize(
    ("now", "missing"),
    [
        (datetime(2028, 6, 1, tzinfo=UTC), [2029]),
        (datetime(2029, 2, 1, tzinfo=UTC), [2029, 2030]),
        # 2028-12-31 20:00 UTC is already 2029 in Asia/Kolkata (UTC+5:30)
        (datetime(2028, 12, 31, 20, 0, tzinfo=UTC), [2029, 2030]),
        (datetime(2028, 12, 31, 12, 0, tzinfo=UTC), [2029]),
    ],
)
def test_missing_years_are_judged_in_the_policy_timezone(now: datetime, missing: list[int]) -> None:
    assert holiday_years_missing(preset(), now) == missing
    found = [w for w in policy_warnings(preset(), now) if w.code == "holidays-missing-year"]
    assert [str(y) in w.message for y, w in zip(missing, found, strict=True)] == [True] * len(
        missing
    )
    assert all(w.severity == "high" and "operator-supplied" in w.message for w in found)


def test_no_holidays_at_all_is_flagged_and_disabled_tightening_is_not() -> None:
    bare = PolicyConfig(off_hours=OffHoursPolicy(holidays=frozenset()))
    assert "holidays-none" in codes(bare)
    off = PolicyConfig(off_hours=OffHoursPolicy(enabled=False, holidays=frozenset()))
    assert holiday_years_missing(off, NOW) == []
    assert not codes(off) & {"holidays-none", "holidays-missing-year"}


def test_the_shield_warns_at_startup_when_the_calendar_has_run_out(
    policy: PolicyConfig, verifier: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from tests.conftest import FakeClock

    late = FakeClock(datetime(2029, 3, 1, 5, 30, tzinfo=UTC))
    with caplog.at_level(logging.WARNING):
        Shield(policy, verifier, clock=late.now, monotonic=late.monotonic).close()
    assert "off_hours.holidays has no entries for 2029" in caplog.text
    caplog.clear()
    now = FakeClock()
    with caplog.at_level(logging.WARNING):
        Shield(policy, verifier, clock=now.now, monotonic=now.monotonic).close()
    assert "holidays" not in caplog.text


def test_a_fixed_date_holiday_still_tightens(policy: PolicyConfig) -> None:
    from redhand_fintech_shield.detectors import OffHoursEvaluator

    evaluator = OffHoursEvaluator(policy)
    # 2027-01-26 (Republic Day) is a Tuesday: only the new calendar entry makes it off-hours
    day = datetime(2027, 1, 26, 6, 0, tzinfo=UTC)
    assert evaluator.reason(day) is not None and "public holiday" in (evaluator.reason(day) or "")
    assert date(2027, 1, 26) in policy.off_hours.holidays


# --------------------------------------------------------------------------------------
# Other warnings: each has a positive and a negative case
# --------------------------------------------------------------------------------------


def exemption(**kw: Any) -> Exemption:
    params: dict[str, Any] = {
        "id": "ex",
        "rules": frozenset({"CIAD-2026-0058.R3.hitl_required"}),
        "reason": "Sample exemption for diagnostics",
        "approved_by": "x",
        "starts_at": NOW - timedelta(days=10),
        "expires_at": NOW + timedelta(days=30),
        "match": ExemptionMatch(tools=frozenset({"t"})),
    }
    params.update(kw)
    return Exemption(**params)


def test_exemption_warnings() -> None:
    base = preset()
    assert not codes(base) & {"exemption-expired", "exemption-expiring"}
    expired = base.model_copy(
        update={"exemptions": (exemption(expires_at=NOW - timedelta(days=1)),)}
    )
    expiring = base.model_copy(
        update={"exemptions": (exemption(expires_at=NOW + timedelta(days=3)),)}
    )
    healthy = base.model_copy(update={"exemptions": (exemption(),)})
    assert "exemption-expired" in codes(expired)
    assert "exemption-expiring" in codes(expiring) and "exemption-expired" not in codes(expiring)
    assert not codes(healthy) & {"exemption-expired", "exemption-expiring"}


def test_token_key_warnings(tmp_path: Path) -> None:
    def keys(*retire: datetime | None) -> tuple[TokenKeyConfig, ...]:
        return tuple(
            TokenKeyConfig(kid=f"k{i}", public_key_path=tmp_path / "k.pem", retire_at=r)
            for i, r in enumerate(retire)
        )

    base = preset()
    live = base.model_copy(update={"token_keys": keys(None, NOW + timedelta(days=30))})
    retiring = base.model_copy(update={"token_keys": keys(None, NOW + timedelta(days=2))})
    retired = base.model_copy(update={"token_keys": keys(None, NOW - timedelta(days=1))})
    dead = base.model_copy(update={"token_keys": keys(NOW - timedelta(days=1))})
    assert not codes(live) & {"key-retired", "key-retiring", "no-live-token-key"}
    assert "key-retiring" in codes(retiring) and "key-retired" not in codes(retiring)
    assert "key-retired" in codes(retired) and "no-live-token-key" not in codes(retired)
    assert {"key-retired", "no-live-token-key"} <= codes(dead)
    critical = [w for w in policy_warnings(dead, NOW) if w.code == "no-live-token-key"]
    assert critical[0].severity == "critical"


def test_identity_and_approval_warnings(tmp_path: Path) -> None:
    base = preset()
    # the shipped preset has no key configured, so it cannot tell you about an audience
    assert "no-audience" not in codes(base)
    keyed = base.model_copy(update={"verifier_public_key_path": tmp_path / "k.pem"})
    assert "no-audience" in codes(keyed)
    assert "no-audience" not in codes(keyed.model_copy(update={"audience": "gateway"}))
    assert "no-approver-key" in codes(base)
    with_approver = base.model_copy(
        update={
            "approval": base.approval.model_copy(
                update={
                    "verifier_public_key_path": tmp_path / "a.pem",
                    "allow_legacy_step_up": False,
                }
            )
        }
    )
    assert not codes(with_approver) & {"no-approver-key", "legacy-step-up"}
    assert "legacy-step-up" in codes(base)


def test_mode_rule_cap_and_aggregation_warnings() -> None:
    base = preset()
    assert not codes(base) & {
        "observe-only",
        "rule-disabled",
        "shadow-rule",
        "no-cumulative-cap",
        "no-aggregation",
    }
    assert "observe-only" in codes(base.model_copy(update={"mode": Mode.OBSERVE_ONLY}))
    off = base.model_copy(update={"rules": {R_STRUCTURING: RuleOverride(enabled=False)}})
    shadow = base.model_copy(
        update={"rules": {R_STRUCTURING: RuleOverride(mode=Mode.OBSERVE_ONLY)}}
    )
    assert "rule-disabled" in codes(off) and "shadow-rule" not in codes(off)
    assert "shadow-rule" in codes(shadow) and "rule-disabled" not in codes(shadow)
    bare = PolicyConfig()
    assert {"no-cumulative-cap", "no-aggregation"} <= codes(bare)


def test_a_warning_prints_with_its_severity_and_code() -> None:
    [w] = [w for w in policy_warnings(preset(), NOW) if w.code == "legacy-step-up"]
    assert str(w).startswith("[low] legacy-step-up: ")


# --------------------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------------------


def test_doctor_lists_warnings_and_strict_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--now", "2026-11-23T08:00:00+00:00"]) == 0
    out = capsys.readouterr().out
    assert "no-approver-key" in out and "warning(s) at 2026-11-23T08:00:00+00:00" in out
    assert main(["doctor", "--strict", "--now", "2026-11-23T08:00:00"]) == 1  # naive means UTC
    capsys.readouterr()
    assert main(["doctor", str(PRESET), "--now", "2029-03-01T00:00:00+00:00"]) == 0
    assert "holidays-missing-year" in capsys.readouterr().out
