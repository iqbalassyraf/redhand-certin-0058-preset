"""Phase 3.5 B: rule catalog and preset manifest.

Rationale: a host application must be able to ask the preset what it enforces without reading
code. The catalog is only trustworthy if it cannot drift from the detectors, so tests tie it to
every rule id, to the override/exemption sets, to the generated documentation and to the severities
the detectors really emit.
"""

from __future__ import annotations

import importlib
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest

from redhand_fintech_shield import PolicyConfig, Shield, ToolCallContext, load_policy, protocols
from redhand_fintech_shield import rules as rules_module
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.manifest import (
    ADVISORIES,
    PresetManifest,
    extension_points,
    get_manifest,
    render_rules_markdown,
)
from redhand_fintech_shield.rules import (
    EXEMPTIBLE_RULES,
    OVERRIDABLE_RULES,
    R_HITL,
    R_MICRO_TX,
    R_VELOCITY,
    RULE_CATALOG,
)

ROOT = Path(__file__).resolve().parent.parent


def all_rule_ids() -> set[str]:
    return {v for k, v in vars(rules_module).items() if k.startswith("R_") and isinstance(v, str)}


# --------------------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------------------


def test_catalog_covers_every_rule_id_exactly_once() -> None:
    ids = [r.id for r in RULE_CATALOG]
    assert len(ids) == len(set(ids))
    assert set(ids) == all_rule_ids()


def test_catalog_agrees_with_the_override_and_exemption_sets() -> None:
    assert {r.id for r in RULE_CATALOG if r.overridable} == OVERRIDABLE_RULES
    assert {r.id for r in RULE_CATALOG if r.exemptible} == EXEMPTIBLE_RULES
    assert EXEMPTIBLE_RULES <= OVERRIDABLE_RULES  # you cannot waive what you cannot tune


def test_every_catalog_entry_is_complete_and_consistent() -> None:
    for rule in RULE_CATALOG:
        assert f".R{rule.stage}." in rule.id, rule.id
        assert rule.name == rule.id.rsplit(".", 1)[-1]
        assert rule.advisories and all(a.startswith("CIAD-2026-00") for a in rule.advisories)
        assert len(rule.summary) > 15 and len(rule.rationale) > 40, rule.id
        # a rule that only informs is never tunable or waivable
        if rule.decision == "allow":
            assert not rule.overridable and not rule.exemptible, rule.id


def test_identity_and_containment_rules_are_not_tunable() -> None:
    by_name = {r.name: r for r in RULE_CATALOG}
    for name in ("agent_quarantined", "token_invalid", "staging_to_prod_pivot", "tool_not_pinned"):
        assert not by_name[name].overridable and not by_name[name].exemptible


def test_catalog_severities_match_what_the_detectors_emit(
    make_shield: Callable[..., Shield], make_ctx: Callable[..., ToolCallContext]
) -> None:
    severity = {r.id: r.severity for r in RULE_CATALOG}
    sh = make_shield()
    seen: dict[str, str] = {}
    for _ in range(2):  # two micro-value payments trip the breaker
        ev = sh.evaluate(make_ctx(run="r-micro", amount="1"))
        seen.update({f.rule_id: f.severity for f in ev.findings})
    for _ in range(25):  # a burst on one tool
        ev = sh.evaluate(make_ctx(run="r-burst", tool="list_merchants"))
        seen.update({f.rule_id: f.severity for f in ev.findings})
    ev = sh.evaluate(make_ctx(run="r-hitl", tool="settle_merchant", amount="15000"))
    seen.update({f.rule_id: f.severity for f in ev.findings})
    assert {R_MICRO_TX, R_VELOCITY, R_HITL} <= set(seen)
    for rule_id, got in seen.items():
        assert severity[rule_id] == got, rule_id


# --------------------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------------------


def test_manifest_describes_the_shipped_preset() -> None:
    manifest = get_manifest()
    policy = load_policy()
    assert manifest.preset_id == policy.preset_id
    assert manifest.preset_version == policy.preset_version == "0.2.0"
    assert manifest.schema_version == policy.schema_version
    assert manifest.policy_sha256 == policy.fingerprint()
    assert {a.id for a in manifest.advisories} == {"CIAD-2026-0058", "CIAD-2026-0049"}
    assert manifest.advisories == ADVISORIES
    assert [r.id for r in manifest.rules] == [r.id for r in RULE_CATALOG]


def test_manifest_round_trips_through_json() -> None:
    manifest = get_manifest()
    assert PresetManifest.model_validate_json(manifest.model_dump_json()) == manifest


def test_extension_points_are_every_protocol_in_the_module() -> None:
    names = {e.name for e in extension_points()}
    expected = {
        n
        for n, o in vars(protocols).items()
        if isinstance(o, type) and getattr(o, "_is_protocol", False) and n != "Protocol"
    }
    assert names == expected
    assert {"AuditLogBackend", "QuarantineBackend", "NonceStore", "TelemetrySink"} <= names
    assert all(e.summary for e in extension_points())


def test_unversioned_policy_is_reported_as_such(monkeypatch: pytest.MonkeyPatch) -> None:
    import redhand_fintech_shield as pkg

    bare = PolicyConfig()
    monkeypatch.setattr(pkg, "load_policy", lambda *a, **k: bare)
    assert get_manifest().preset_version == "unversioned"


# --------------------------------------------------------------------------------------
# Generated documentation and wiring
# --------------------------------------------------------------------------------------


def test_rules_document_is_in_sync_with_the_catalog() -> None:
    committed = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert committed.rstrip("\n") == render_rules_markdown(get_manifest()).rstrip("\n"), (
        "docs/rules.md is out of date: run `redhand-shield manifest --markdown > docs/rules.md`"
    )


def test_entry_point_is_declared_and_resolves() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    target = meta["project"]["entry-points"]["redhand.presets"]["certin_ciad_2026_0058"]
    module_name, _, attr = target.partition(":")
    factory = getattr(importlib.import_module(module_name), attr)
    assert isinstance(factory(), PresetManifest)


def test_manifest_command_prints_json_and_markdown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["manifest"]) == 0
    assert PresetManifest.model_validate_json(capsys.readouterr().out) == get_manifest()
    assert main(["manifest", "--markdown"]) == 0
    assert capsys.readouterr().out.startswith("# Rule catalog")
