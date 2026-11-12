"""The runnable demo is part of the product: keep it honest and green."""

from __future__ import annotations

import importlib.util
import sys
from decimal import Decimal
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "examples" / "simulate_crafty_falcon.py"


@pytest.fixture(scope="module")
def sim() -> ModuleType:
    spec = importlib.util.spec_from_file_location("simulate_crafty_falcon", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


def test_enforce_run_stops_all_but_the_first_probe(
    sim: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert sim.main(["--mode", "enforce", "--delay", "0", "--keep", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "RESULT: PASS" in out and "chain BROKEN" in out  # tamper demo is detected
    assert (tmp_path / "enforce" / "audit_trail.jsonl").is_file()


def test_both_modes_contrast_defended_and_undefended(
    sim: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert sim.main(["--delay", "0", "--keep", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "ENFORCE" in out and "OBSERVE-ONLY" in out
    assert "$54,503.50" in out and "$0.50" in out


def test_leaked_funds_accounting(sim: ModuleType) -> None:
    result = sim.RunResult(mode=sim.Mode.ENFORCE)
    result.steps.append(sim.Step(2, "p", True, True, None, Decimal("0.50")))
    result.steps.append(sim.Step(2, "q", True, False, "x", Decimal("1.00")))
    assert result.leaked == Decimal("0.50") and result.stopped == 1
