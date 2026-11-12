from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from redhand_fintech_shield import (
    Env,
    Mode,
    PolicyConfig,
    PolicyLoadError,
    ToolCallContext,
    load_policy,
)
from redhand_fintech_shield.models import OffHoursPolicy

from .conftest import PRESET


def test_bundled_preset_loads_with_advisory_defaults() -> None:
    p = load_policy()
    assert p.preset_id == "certin_ciad_2026_0058"
    assert p.mode is Mode.ENFORCE
    assert p.micro_tx.ceilings["USD"] == Decimal("5.00")
    assert p.micro_tx.max_probes == 2
    assert p.micro_tx.window_seconds == 60
    assert p.hitl.thresholds["USD"] == Decimal("10000")
    assert {"settle_merchant", "initiate_disbursement"} <= p.hitl.protected_tools


def test_policy_is_immutable() -> None:
    with pytest.raises(ValidationError):
        load_policy().mode = Mode.OBSERVE_ONLY


def test_unknown_policy_key_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text(PRESET.read_text() + "\nsurprise_key: true\n")
    with pytest.raises(PolicyLoadError):
        PolicyConfig.from_yaml(bad)


def test_float_money_in_yaml_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("micro_tx:\n  ceilings:\n    USD: 5.00\n")  # unquoted -> YAML float
    with pytest.raises(PolicyLoadError):
        PolicyConfig.from_yaml(bad)


def test_missing_and_non_mapping_policy(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError):
        PolicyConfig.from_yaml(tmp_path / "nope.yaml")
    listy = tmp_path / "l.yaml"
    listy.write_text("- a\n- b\n")
    with pytest.raises(PolicyLoadError):
        PolicyConfig.from_yaml(listy)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timezone": "Mars/Olympus"},
        {"business_hours": (18, 9)},
        {"business_hours": (0, 25)},
        {"weekend_days": frozenset({7})},
        {"tighten_factor": 0},
        {"tighten_factor": 1.5},
    ],
)
def test_off_hours_validation(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        OffHoursPolicy(**kwargs)  # type: ignore[arg-type]


def test_context_rejects_float_negative_and_orphan_currency() -> None:
    base = {"agent_run_id": "r", "tool_name": "t", "target_env": Env.PROD, "token": "x"}
    with pytest.raises(ValidationError):
        ToolCallContext(**base, amount=1.5, currency="USD")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ToolCallContext(**base, amount=Decimal("-1"), currency="USD")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ToolCallContext(**base, amount=Decimal("NaN"), currency="USD")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ToolCallContext(**base, currency="USD")  # type: ignore[arg-type]


def test_context_normalizes_currency_and_accepts_string_amount() -> None:
    ctx = ToolCallContext(
        agent_run_id="r",
        tool_name="t",
        target_env=Env.PROD,
        token="x",
        amount=Decimal("1.00"),
        currency="usd",
    )
    assert ctx.currency == "USD"
    assert ctx.amount == Decimal("1.00")
