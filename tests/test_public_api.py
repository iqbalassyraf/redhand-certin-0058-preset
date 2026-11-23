"""Phase 3.5 F: a stable public API.

Rationale: the main RedHand app imports this package. A rename, a removed parameter or a changed
signature must be a deliberate, recorded decision, not a side effect. The committed snapshot makes
every such change visible in review, and the deprecation helper gives callers a release of notice.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import pytest

import redhand_fintech_shield as package
from redhand_fintech_shield import Decision, Mode, PolicyConfig, Shield
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield._deprecation import warn_deprecated
from redhand_fintech_shield.api_snapshot import (
    default_snapshot_path,
    describe,
    diff,
    render,
    snapshot,
)
from tests.conftest import FakeClock

COMMITTED = Path(__file__).resolve().parent.parent / "docs" / "public_api.json"


# --------------------------------------------------------------------------------------
# The committed snapshot
# --------------------------------------------------------------------------------------


def test_public_api_matches_the_committed_snapshot() -> None:
    committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
    changes = diff(committed, snapshot())
    assert changes == [], (
        f"public API changed: {changes}. If this is intended, run "
        "`redhand-shield api --out docs/public_api.json` and record it in CHANGELOG.md under "
        "Added, Changed, Deprecated or Removed (see CONTRIBUTING.md)"
    )
    assert COMMITTED.read_text(encoding="utf-8") == render(snapshot())  # byte-identical
    assert default_snapshot_path() == COMMITTED


def test_every_exported_name_exists_is_unique_and_public() -> None:
    names = package.__all__
    assert len(names) == len(set(names))
    assert all(hasattr(package, n) for n in names)
    assert all(n == "__version__" or not n.startswith("_") for n in names)


def test_the_host_facing_pieces_of_this_phase_are_exported() -> None:
    for name in (
        "get_manifest",
        "PresetManifest",
        "policy_fingerprint",
        "RULE_CATALOG",
        "WindowStore",
        "WindowStoreFull",
        "InMemoryWindowStore",
        "RevocationStore",
        "KeyRing",
        "NonceStore",
        "load_policy",
    ):
        assert name in package.__all__, name


# --------------------------------------------------------------------------------------
# The snapshot notices breaking changes
# --------------------------------------------------------------------------------------


def test_diff_reports_removed_added_and_changed_names() -> None:
    old = {"A": {"kind": "function", "signature": "(x:int)"}, "B": {"kind": "constant"}}
    new = {"A": {"kind": "function", "signature": "(x:int, y:int)"}, "C": {"kind": "constant"}}
    assert diff(old, new) == ["removed: B", "added: C", "changed: A"]
    assert diff(old, old) == []


def test_describe_sees_signature_field_enum_and_method_changes() -> None:
    def before(a: int, *, b: str = "x") -> None: ...
    def renamed(a: int, *, c: str = "x") -> None: ...
    def retyped(a: str, *, b: str = "x") -> None: ...

    assert describe(before) != describe(renamed) != describe(retyped)
    assert describe(Decision)["kind"] == "enum" and "BLOCK" in describe(Decision)["members"]
    assert describe(PolicyConfig)["kind"] == "model" and "hitl" in describe(PolicyConfig)["fields"]
    shield = describe(Shield)
    assert shield["kind"] == "class" and "evaluate" in shield["methods"]
    assert describe(Mode.ENFORCE) == {"kind": "constant", "type": "Mode"}
    assert describe(package.ShieldError)["kind"] == "exception"
    assert describe(package.WindowStore)["kind"] == "protocol"


def test_a_removed_method_or_changed_parameter_of_a_shipped_class_changes_the_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = describe(Shield)
    assert {"evaluate", "guard", "close"} <= original["methods"].keys()

    monkeypatch.delattr(Shield, "close")
    assert "close" not in describe(Shield)["methods"]
    assert diff({"Shield": original}, {"Shield": describe(Shield)}) == ["changed: Shield"]
    monkeypatch.undo()

    def evaluate(self: Shield, ctx: Any, extra: int) -> None: ...

    monkeypatch.setattr(Shield, "evaluate", evaluate)
    changed = describe(Shield)["methods"]["evaluate"]
    assert "extra:int" in changed and changed != original["methods"]["evaluate"]
    monkeypatch.undo()
    assert describe(Shield) == original  # the snapshot is a pure function of the code


def test_signatures_carry_no_memory_addresses() -> None:
    text = render(snapshot())
    assert " at 0x" not in text
    assert "<redhand_fintech_shield.crypto.utcnow>" in text  # callable defaults are named


# --------------------------------------------------------------------------------------
# Deprecation policy
# --------------------------------------------------------------------------------------


def test_warn_deprecated_says_what_to_use_and_blames_the_caller() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warn_deprecated("old_thing()", "new_thing()")
    [w] = caught
    assert issubclass(w.category, DeprecationWarning)
    assert "old_thing() is deprecated" in str(w.message) and "use new_thing()" in str(w.message)
    assert "a future minor release" in str(w.message)


def test_the_alias_arguments_warn_and_still_work(
    policy: PolicyConfig, verifier: Any, clock: FakeClock
) -> None:
    from redhand_fintech_shield import QuarantineRegistry

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        shield = Shield(
            policy,
            verifier,
            quarantine_tracker=QuarantineRegistry(),
            clock=clock.now,
            monotonic=clock.monotonic,
        )
    [w] = [c for c in caught if issubclass(c.category, DeprecationWarning)]
    assert "quarantine_tracker=...) is deprecated" in str(w.message) and "quarantine=" in str(
        w.message
    )
    assert w.filename.endswith("test_public_api.py")  # blamed on the caller, not on the library
    assert shield.quarantine is not None
    shield.close()
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the supported spelling is silent
        supported = Shield(policy, verifier, quarantine=QuarantineRegistry(), clock=clock.now)
    supported.close()


# --------------------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------------------


def test_api_command_prints_writes_and_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["api"]) == 0
    assert json.loads(capsys.readouterr().out) == snapshot()
    target = tmp_path / "api.json"
    assert main(["api", "--out", str(target)]) == 0
    assert main(["api", "--check", "--out", str(target)]) == 0
    assert "public API OK" in capsys.readouterr().out
    assert main(["api", "--check"]) == 0  # the committed snapshot

    committed = json.loads(target.read_text(encoding="utf-8"))
    committed["Shield"]["init"] = "(policy:PolicyConfig)"
    del committed["Decision"]
    committed["Ghost"] = {"kind": "constant", "type": "int"}
    target.write_text(json.dumps(committed), encoding="utf-8")
    assert main(["api", "--check", "--out", str(target)]) == 1
    err = capsys.readouterr().err
    assert "changed: Shield" in err and "added: Decision" in err and "removed: Ghost" in err
    assert "CHANGELOG.md" in err

    assert main(["api", "--check", "--out", str(tmp_path / "missing.json")]) == 1
    assert "cannot read" in capsys.readouterr().err
