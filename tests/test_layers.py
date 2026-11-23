"""Phase 3 Milestone 5 tests: composable policies.

Rationale: an operator must be able to adjust the shipped preset without forking it, and must not
be able to weaken it by accident. Overlays can only tighten; each loosening has to be named in
``loosen:`` and is recorded; a base can lock fields. Rules can run in shadow or be switched off
without touching the identity controls, and an exemption is a named, expiring, audited waiver of
a human step-up requirement, never of a block.
"""

from __future__ import annotations

import itertools
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import redhand_fintech_shield
from redhand_fintech_shield import (
    AgentTokenIssuer,
    Decision,
    Env,
    Exemption,
    ExemptionMatch,
    Mode,
    PolicyConfig,
    PolicyLoadError,
    RuleOverride,
    Shield,
    ToolCallContext,
    load_policy,
)
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.detectors import (
    R_CUMULATIVE_CAP,
    R_EXEMPTION_APPLIED,
    R_HITL,
    R_NEW_BENEFICIARY,
    R_OFF_HOURS_HITL,
    R_SEQUENCE,
    R_STRUCTURING,
    R_TOKEN_INVALID,
    R_VELOCITY,
)
from redhand_fintech_shield.interceptor import Evaluation
from redhand_fintech_shield.layers import (
    DIRECTIONS,
    META_KEYS,
    check_tightening,
    find_loosenings,
)
from redhand_fintech_shield.models import CumulativeCapPolicy, M42Finding
from tests.conftest import PRESET, WEEKEND_UTC, FakeClock

TOOL = "settle_merchant"
SHADOW = RuleOverride(mode=Mode.OBSERVE_ONLY)


def _paid(**kw: Any) -> str:
    return "paid"


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def overlay(tmp_path: Path, body: str, *, extends: str = "certin_ciad_2026_0058") -> Path:
    return write(tmp_path, "overlay.yaml", f"extends: {extends}\n{body}")


def load(tmp_path: Path, body: str, **kw: Any) -> PolicyConfig:
    return load_policy(overlay(tmp_path, body, **kw))


def refused(tmp_path: Path, body: str, message: str, **kw: Any) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load(tmp_path, body, **kw)


# --------------------------------------------------------------------------------------
# Loading and merging
# --------------------------------------------------------------------------------------


def test_overlay_extends_the_bundled_preset_by_id_and_records_provenance(tmp_path: Path) -> None:
    policy = load(tmp_path, "hitl:\n  thresholds:\n    USD: '5000'\n")
    base = PolicyConfig.from_yaml(PRESET)
    assert policy.hitl.thresholds["USD"] == Decimal("5000")
    assert policy.hitl.thresholds["INR"] == base.hitl.thresholds["INR"]  # untouched keys survive
    assert policy.provenance is not None
    assert [c.split("@")[0] for c in policy.provenance.chain] == [
        "certin_ciad_2026_0058.yaml",
        "overlay.yaml",
    ]
    assert all("@sha256:" in c for c in policy.provenance.chain)
    assert policy.provenance.loosened == ()
    assert "hitl.protected_tools" in policy.provenance.locked


def test_extends_a_relative_file_and_chains_three_deep(tmp_path: Path) -> None:
    write(tmp_path, "a.yaml", "preset_id: a\nhitl:\n  thresholds: {USD: '9000'}\n")
    write(tmp_path, "b.yaml", "extends: ./a.yaml\nhitl:\n  thresholds: {USD: '8000'}\n")
    top = write(tmp_path, "c.yaml", "extends: b.yaml\nhitl:\n  thresholds: {USD: '7000'}\n")
    policy = load_policy(top)
    assert policy.hitl.thresholds["USD"] == Decimal("7000")
    assert policy.provenance is not None and len(policy.provenance.chain) == 3


def test_list_append_with_plus_and_replace_with_a_superset(tmp_path: Path) -> None:
    appended = load(
        tmp_path,
        "structuring:\n  protected_tools+: [extra_tool]\n"
        "tool_bindings:\n  tools:\n    extra_tool: {amount: amount}\n",
    )
    assert appended.structuring.protected_tools == {
        "settle_merchant",
        "initiate_disbursement",
        "bulk_payout",
        "extra_tool",
    }
    replaced = load(
        tmp_path,
        "structuring:\n  protected_tools: [settle_merchant, initiate_disbursement, bulk_payout, x]\n"  # noqa: E501
        "tool_bindings:\n  tools:\n    x: {amount: amount}\n",
    )
    assert "x" in replaced.structuring.protected_tools


def test_plus_requires_lists(tmp_path: Path) -> None:
    refused(tmp_path, "mode+: [x]\n", "can only append a list to a list")
    refused(tmp_path, "hitl:\n  thresholds+: [x]\n", "can only append a list to a list")


def test_loader_errors_are_clear(tmp_path: Path) -> None:
    refused(tmp_path, "", "does not exist", extends="nope_not_a_preset")
    refused(tmp_path, "", "does not exist", extends="./missing.yaml")
    with pytest.raises(PolicyLoadError, match="must name a preset id or a file"):
        load_policy(write(tmp_path, "o.yaml", "extends: 5\n"))
    with pytest.raises(PolicyLoadError, match="must name a preset id or a file"):
        load_policy(write(tmp_path, "o.yaml", "extends: '  '\n"))
    with pytest.raises(PolicyLoadError, match="`loosen` only makes sense with `extends`"):
        load_policy(write(tmp_path, "o.yaml", "loosen: [mode]\n"))
    with pytest.raises(PolicyLoadError, match="`loosen` must be a list of field paths"):
        load_policy(write(tmp_path, "o.yaml", "extends: certin_ciad_2026_0058\nloosen: mode\n"))
    with pytest.raises(PolicyLoadError, match="`locked` must be a list of field paths"):
        load_policy(write(tmp_path, "o.yaml", "locked: [1, 2]\n"))
    with pytest.raises(PolicyLoadError, match="must be a YAML mapping"):
        load_policy(write(tmp_path, "o.yaml", "- a\n- b\n"))
    with pytest.raises(PolicyLoadError, match="cannot read policy"):
        load_policy(tmp_path / "absent.yaml")
    with pytest.raises(PolicyLoadError, match="cannot read policy"):
        load_policy(write(tmp_path, "o.yaml", "a: [unclosed\n"))
    refused(tmp_path, "surprise_key: 1\n", "invalid policy")  # unknown keys still fail closed


def test_cycles_and_deep_chains_are_refused(tmp_path: Path) -> None:
    write(tmp_path, "a.yaml", "extends: b.yaml\n")
    b = write(tmp_path, "b.yaml", "extends: a.yaml\n")
    with pytest.raises(PolicyLoadError, match="cycle"):
        load_policy(b)
    names = [f"l{i}.yaml" for i in range(7)]
    for lower, upper in itertools.pairwise(names):
        write(tmp_path, lower, f"extends: {upper}\n")
    write(tmp_path, names[-1], "preset_id: end\n")
    with pytest.raises(PolicyLoadError, match="deeper than"):
        load_policy(tmp_path / names[0])


def test_provenance_written_in_a_file_is_ignored_not_trusted(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "p.yaml",
        "provenance:\n  chain: [forged]\n  loosened: []\n  locked: []\n",
    )
    policy = load_policy(path)
    assert policy.provenance is not None and policy.provenance.chain[0].startswith("p.yaml@")


def test_show_policy_output_can_be_loaded_again(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["show-policy", str(PRESET)]) == 0
    printed = capsys.readouterr().out.split("\n", 1)[1]
    again = load_policy(write(tmp_path, "round.yaml", printed))
    assert again.hitl.thresholds == PolicyConfig.from_yaml(PRESET).hitl.thresholds


def test_installed_layout_lookup_for_bundled_preset_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = tmp_path / "share" / "presets"
    shared.mkdir(parents=True)
    (shared / "certin_ciad_2026_0058.yaml").write_text(PRESET.read_text(), encoding="utf-8")
    monkeypatch.setattr(redhand_fintech_shield, "default_preset_path", lambda: shared / "x.yaml")
    assert load(tmp_path / "..", "mode: enforce\n").mode is Mode.ENFORCE


# --------------------------------------------------------------------------------------
# Tighten-only
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "hitl:\n  thresholds: {USD: '5000'}\n",
        "micro_tx:\n  ceilings: {USD: '50'}\n  max_probes: 1\n  window_seconds: 120\n",
        "velocity:\n  max_calls: 10\n  window_seconds: 2\n  max_total_calls: 30\n",
        "structuring:\n  thresholds: {USD: '5000'}\n  min_tx_count: 1\n  window_seconds: 600\n",
        "cumulative_cap:\n  per_run: {USD: '1000'}\n  per_subject: {USD: '2000'}\n  action: block\n",  # noqa: E501
        "new_beneficiary:\n  action: block\n  thresholds: {USD: '500'}\n",
        "sequence:\n  min_recon_calls: 2\n  window_seconds: 60\n  recon_tools+: [more]\n",
        "off_hours:\n  business_hours: [10, 17]\n  tighten_factor: 0.25\n  weekend_days+: [4]\n",
        "approval:\n  allow_legacy_step_up: false\n  max_ttl_seconds: 60\n",
        "max_token_ttl_seconds: 600\nexemption_max_days: 30\naudit_fsync: true\n",
        "audit_path: other_audit.jsonl\nissuer: someone\nquarantine_journal_path: q2.jsonl\n",
        "mode: enforce\nquarantine_on_block: true\n",
        "tool_bindings:\n  legacy_fallback: false\n  tools:\n    brand_new_tool: {amount: amt}\n",
    ],
)
def test_tightening_and_deployment_settings_load_without_loosen(tmp_path: Path, body: str) -> None:
    policy = load(tmp_path, body)
    assert policy.provenance is not None and policy.provenance.loosened == ()


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ("hitl:\n  thresholds: {USD: '20000'}\n", "hitl.thresholds.USD"),
        ("hitl:\n  thresholds: {USD: '10000', EUR: '100'}\n", "hitl.thresholds.EUR"),
        ("micro_tx:\n  ceilings: {USD: '1'}\n", "micro_tx.ceilings.USD"),
        ("micro_tx:\n  ceilings: {USD: '5', EUR: '5'}\n", "micro_tx.ceilings.EUR"),
        ("micro_tx:\n  max_probes: 5\n", "micro_tx.max_probes"),
        ("micro_tx:\n  window_seconds: 5\n", "micro_tx.window_seconds"),
        ("velocity:\n  max_calls: 100\n", "velocity.max_calls"),
        ("velocity:\n  max_total_calls: null\n", "velocity.max_total_calls"),
        ("velocity:\n  window_seconds: 0.5\n", "velocity.window_seconds"),
        ("structuring:\n  enabled: false\n", "structuring.enabled"),
        ("structuring:\n  scopes: [run]\n", "structuring.scopes"),
        ("structuring:\n  protected_tools: [settle_merchant]\n", "structuring.protected_tools"),
        ("structuring:\n  min_tx_count: 9\n", "structuring.min_tx_count"),
        ("cumulative_cap:\n  enabled: false\n", "cumulative_cap.enabled"),
        ("cumulative_cap:\n  per_run: {USD: '90000'}\n", "cumulative_cap.per_run.USD"),
        (
            "cumulative_cap:\n  per_subject: {USD: '200000', EUR: '1'}\n",
            "cumulative_cap.per_subject.EUR",
        ),
        ("new_beneficiary:\n  enabled: false\n", "new_beneficiary.enabled"),
        ("new_beneficiary:\n  known_beneficiaries: [a@b]\n", "new_beneficiary.known_beneficiaries"),
        ("sequence:\n  enabled: false\n", "sequence.enabled"),
        ("sequence:\n  recon_tools: [only_one]\n", "sequence.recon_tools"),
        ("off_hours:\n  business_hours: [8, 19]\n", "off_hours.business_hours"),
        ("off_hours:\n  tighten_factor: 1\n", "off_hours.tighten_factor"),
        ("off_hours:\n  mandatory_hitl: false\n", "off_hours.mandatory_hitl"),
        ("off_hours:\n  timezone: UTC\n", "off_hours.timezone"),
        ("approval:\n  max_ttl_seconds: 3000\n", "approval.max_ttl_seconds"),
        ("max_token_ttl_seconds: 7200\n", "max_token_ttl_seconds"),
        ("mode: observe_only\n", "mode"),
        ("exemption_max_days: 200\n", "exemption_max_days"),
        ("aggregation:\n  rates: {INR: '0.5'}\n", "aggregation.rates"),
        (
            "tool_bindings:\n  tools:\n    settle_merchant: {amount: decoy}\n",
            "tool_bindings.tools.settle_merchant",
        ),
    ],
)
def test_every_kind_of_loosening_is_refused_with_the_field_named(
    tmp_path: Path, body: str, field: str
) -> None:
    with pytest.raises(PolicyLoadError) as err:
        load(tmp_path, body)
    assert field in str(err.value) and "loosen:" in str(err.value)


def test_loosen_allows_exactly_what_it_lists_and_is_recorded(tmp_path: Path) -> None:
    policy = load(
        tmp_path,
        "loosen: [hitl.thresholds.USD, 'micro_tx.max_*']\n"
        "hitl:\n  thresholds: {USD: '20000'}\n"
        "micro_tx:\n  max_probes: 5\n",
    )
    assert policy.hitl.thresholds["USD"] == Decimal("20000")
    assert policy.provenance is not None
    assert policy.provenance.loosened == (
        "hitl.thresholds.USD: 10000.00 -> 20000" if False else policy.provenance.loosened
    )
    assert any(item.startswith("hitl.thresholds.USD") for item in policy.provenance.loosened)
    assert any(item.startswith("micro_tx.max_probes") for item in policy.provenance.loosened)


def test_wildcard_loosen_covers_a_whole_map(tmp_path: Path) -> None:
    policy = load(
        tmp_path,
        "loosen: ['hitl.thresholds.*']\n"
        "hitl:\n  thresholds: {USD: '20000', INR: '2000000', EUR: '5'}\n",
    )
    assert policy.hitl.thresholds["EUR"] == Decimal("5")


def test_loosening_something_not_listed_is_still_refused_when_others_are(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError) as err:
        load(
            tmp_path,
            "loosen: [hitl.thresholds.USD]\n"
            "hitl:\n  thresholds: {USD: '20000'}\n"
            "velocity:\n  max_calls: 100\n",
        )
    assert "velocity.max_calls" in str(err.value) and "hitl.thresholds.USD" not in str(err.value)


def test_a_stale_loosen_entry_is_an_error(tmp_path: Path) -> None:
    refused(
        tmp_path,
        "loosen: [hitl.thresholds.USD]\nhitl:\n  thresholds: {USD: '5000'}\n",
        "does not loosen anything",
    )


def test_locked_fields_can_never_be_loosened_even_if_listed(tmp_path: Path) -> None:
    refused(
        tmp_path,
        "loosen: [hitl.protected_tools]\nhitl:\n  protected_tools: [settle_merchant]\n",
        r"hitl\.protected_tools .* is locked by the base policy",
    )
    refused(
        tmp_path,
        "loosen: [quarantine_on_block]\nquarantine_on_block: false\n",
        "is locked by the base policy",
    )


def test_locked_in_a_middle_layer_binds_everything_above_it(tmp_path: Path) -> None:
    write(tmp_path, "mid.yaml", "extends: certin_ciad_2026_0058\nlocked: [mode]\n")
    top = write(tmp_path, "top.yaml", "extends: mid.yaml\nloosen: [mode]\nmode: observe_only\n")
    with pytest.raises(PolicyLoadError, match="locked by the base policy"):
        load_policy(top)
    ok = write(tmp_path, "ok.yaml", "extends: mid.yaml\nhitl:\n  thresholds: {USD: '1'}\n")
    assert load_policy(ok).provenance is not None
    assert "mode" in load_policy(ok).provenance.locked  # type: ignore[union-attr]


def test_unclassified_fields_default_to_must_not_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delitem(DIRECTIONS, "approval.max_nonces")
    monkeypatch.delitem(DIRECTIONS, "issuer")
    refused(tmp_path, "approval:\n  max_nonces: 5\n", "approval.max_nonces .* must not change")
    refused(tmp_path, "issuer: other\n", "issuer .* must not change")


def test_every_policy_field_has_a_direction() -> None:
    """A field added to the policy must be classified, or it silently becomes 'fixed'."""
    from pydantic import BaseModel

    missing: list[str] = []
    for name, field in PolicyConfig.model_fields.items():
        if name in DIRECTIONS:
            continue
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            missing += [
                f"{name}.{sub}"
                for sub in annotation.model_fields
                if f"{name}.{sub}" not in DIRECTIONS
            ]
        else:
            missing.append(name)
    assert missing == []
    assert META_KEYS == ("extends", "loosen", "locked")


def _base(**updates: Any) -> PolicyConfig:
    return PolicyConfig.model_validate(updates)


def test_loosenings_a_file_overlay_cannot_express_are_still_detected() -> None:
    # a deep merge cannot delete a key, so these are checked on two policies directly
    base = _base(
        tool_bindings={"tools": {"pay": {"amount": "a"}, "pay2": {"amount": "b"}}},
        cumulative_cap={"enabled": True, "per_run": {"USD": "10"}},
        rules={R_STRUCTURING: {"severity": "high"}},
        hitl={"thresholds": {"USD": "1", "EUR": "1"}},
    )
    merged = _base(
        tool_bindings={"tools": {"pay": {"amount": "a"}}},
        cumulative_cap={"enabled": True, "per_subject": {"USD": "10"}},
        rules={R_STRUCTURING: {"severity": "low"}},
        hitl={"thresholds": {"USD": "1"}},
    )
    paths = {item.path for item in find_loosenings(base, merged)}
    assert paths == {
        "tool_bindings.tools.pay2",
        "cumulative_cap.per_run",
        f"rules[{R_STRUCTURING}].severity",
    }  # a dropped currency threshold fails closed, which is tighter, so it is not listed


def test_scope_enum_interval_and_subset_kinds_in_both_directions(tmp_path: Path) -> None:
    write(
        tmp_path,
        "base.yaml",
        "structuring:\n  protected_tools: [a]\n"
        "cumulative_cap:\n  enabled: true\n  protected_tools: []\n  per_run: {USD: '5'}\n"
        "new_beneficiary:\n  action: block\n"
        "off_hours:\n  business_hours: [9, 18]\n"
        "audit_fsync: true\n"
        "approval:\n  allow_legacy_step_up: false\n",
    )

    def attempt(body: str) -> None:
        load_policy(write(tmp_path, "o.yaml", f"extends: base.yaml\n{body}"))

    for ok in (
        "structuring:\n  protected_tools: [a, b]\n",
        "structuring:\n  protected_tools: []\n",  # empty means all tools: broader
        "off_hours:\n  business_hours: [10, 17]\n",
    ):
        attempt(ok)
    for bad, field in (
        ("structuring:\n  protected_tools: [b]\n", "structuring.protected_tools"),
        ("cumulative_cap:\n  protected_tools: [x]\n", "cumulative_cap.protected_tools"),
        ("new_beneficiary:\n  action: hitl_required\n", "new_beneficiary.action"),
        ("off_hours:\n  business_hours: [8, 18]\n", "off_hours.business_hours"),
        ("off_hours:\n  business_hours: [9, 19]\n", "off_hours.business_hours"),
        ("audit_fsync: false\n", "audit_fsync"),
        ("approval:\n  allow_legacy_step_up: true\n", "approval.allow_legacy_step_up"),
    ):
        with pytest.raises(PolicyLoadError, match=field.replace(".", r"\.")):
            attempt(bad)


def test_check_tightening_returns_nothing_for_identical_policies() -> None:
    base = PolicyConfig.from_yaml(PRESET)
    assert check_tightening(base, base, loosen=[], locked=[]) == ()


# --------------------------------------------------------------------------------------
# Rule overrides
# --------------------------------------------------------------------------------------


@pytest.fixture
def mint(issuer: AgentTokenIssuer, clock: FakeClock) -> Callable[..., str]:
    def _mint(run: str, sub: str = "svc", env: Env = Env.PROD) -> str:
        return issuer.mint(
            subject=sub,
            agent_run_id=run,
            env=env,
            allowed_tools=(TOOL, "list_merchants", "charge_card"),
            now=clock.now(),
        )

    return _mint


def pay(
    token: str,
    run: str = "run-1",
    amount: str = "6000",
    *,
    beneficiary: str | None = None,
    beneficiaries: tuple[str, ...] = (),
    tool: str = TOOL,
    env: Env = Env.PROD,
) -> ToolCallContext:
    return ToolCallContext(
        agent_run_id=run,
        tool_name=tool,
        target_env=env,
        token=token,
        amount=Decimal(amount),
        currency="USD",
        beneficiary=beneficiary,
        beneficiaries=beneficiaries,
    )


def test_rules_cannot_override_identity_or_unknown_rules() -> None:
    with pytest.raises(ValidationError, match="not overridable"):
        PolicyConfig(rules={R_TOKEN_INVALID: RuleOverride(enabled=False)})
    with pytest.raises(ValidationError, match="not overridable"):
        PolicyConfig(rules={"made.up.rule": RuleOverride()})


def test_a_shadow_rule_reports_but_never_blocks_or_quarantines(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh = make_shield(rules={R_STRUCTURING: SHADOW})
    token = mint("run-1")
    assert sh.evaluate(pay(token)).decision is Decision.ALLOW
    second = sh.evaluate(pay(token))  # 12,000 in 300 s would trip structuring
    assert second.decision is Decision.ALLOW
    [finding] = [f for f in second.findings if f.rule_id == R_STRUCTURING]
    assert finding.would_have_blocked and finding.enforced is False
    assert finding.decision is Decision.BLOCK
    assert not sh.quarantine.is_quarantined("run-1")
    assert sh.evaluate(pay(token, amount="1")).decision is Decision.ALLOW


def test_shadow_and_enforce_runs_report_the_same_finding(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh_shadow = make_shield(rules={R_STRUCTURING: SHADOW})
    sh_enforce = make_shield()
    token = mint("run-1")
    for sh in (sh_shadow, sh_enforce):
        sh.evaluate(pay(token))
    a, b = sh_shadow.evaluate(pay(token)), sh_enforce.evaluate(pay(token))
    assert [f.rule_id for f in a.findings] == [f.rule_id for f in b.findings]
    assert b.decision is Decision.BLOCK and a.decision is Decision.ALLOW


def test_a_shadow_hitl_gate_does_not_hold_the_call_or_ask_for_approval(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh = make_shield(rules={R_HITL: SHADOW, R_NEW_BENEFICIARY: SHADOW})
    ev = sh.evaluate(pay(mint("run-1"), amount="15000", beneficiary="acct-9"))
    assert ev.decision is Decision.ALLOW and ev.approval_request is None
    assert {f.rule_id for f in ev.findings} >= {R_HITL, R_NEW_BENEFICIARY}
    assert all(not f.enforced for f in ev.findings if f.rule_id in (R_HITL, R_NEW_BENEFICIARY))


def test_a_disabled_rule_is_silent_and_a_severity_override_relabels(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh = make_shield(
        rules={
            R_VELOCITY: RuleOverride(enabled=False),
            R_STRUCTURING: RuleOverride(severity="low"),
        },
        sequence=PolicyConfig.from_yaml(PRESET).sequence.model_copy(update={"enabled": False}),
    )
    token = mint("run-v")
    results = [sh.evaluate(pay(token, "run-v", "1", tool="charge_card")) for _ in range(60)]
    assert all(r.decision is Decision.ALLOW or "micro" in str(r.findings) for r in results[:1])
    assert not any(f.rule_id == R_VELOCITY for r in results for f in r.findings)

    sh2 = make_shield(rules={R_STRUCTURING: RuleOverride(severity="low")})
    t2 = mint("run-s")
    sh2.evaluate(pay(t2, "run-s"))
    tripped = sh2.evaluate(pay(t2, "run-s"))
    [finding] = [f for f in tripped.findings if f.rule_id == R_STRUCTURING]
    assert finding.severity == "low" and tripped.decision is Decision.BLOCK


def test_primary_finding_prefers_an_enforced_finding_over_a_shadow_one() -> None:
    def finding(rule: str, decision: Decision, enforced: bool) -> M42Finding:
        return M42Finding(
            finding_id=rule,
            rule_id=rule,
            severity="high",
            stage=2,
            decision=decision,
            would_have_blocked=True,
            enforced=enforced,
            agent_run_id="r",
            tool_name="t",
            detail=rule,
            observed_at=datetime.now(UTC),
        )

    shadow = finding("shadow", Decision.BLOCK, False)
    real = finding("real", Decision.HITL_REQUIRED, True)
    assert Evaluation(Decision.HITL_REQUIRED, [shadow, real], 1).primary_finding() is real
    # with nothing enforced (global observe-only) the first finding is still reported
    assert Evaluation(Decision.ALLOW, [shadow], 1).primary_finding() is shadow
    assert Evaluation(Decision.ALLOW, [], 1).primary_finding() is None


def test_a_shadowed_cap_does_not_block_and_the_payment_is_still_counted(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    base = PolicyConfig.from_yaml(PRESET)
    sh = make_shield(
        structuring=base.structuring.model_copy(update={"enabled": False}),
        cumulative_cap=CumulativeCapPolicy(
            enabled=True, protected_tools=frozenset({TOOL}), per_run={"USD": Decimal("10000")}
        ),
        rules={R_CUMULATIVE_CAP: SHADOW},
    )
    token = mint("run-c")
    sh.evaluate(pay(token, "run-c"))
    second = sh.evaluate(pay(token, "run-c"))
    third = sh.evaluate(pay(token, "run-c"))
    assert second.decision is third.decision is Decision.ALLOW
    assert "18000" in next(f.detail for f in third.findings if f.rule_id == R_CUMULATIVE_CAP)


def test_rule_override_in_an_overlay_needs_loosen_for_shadow_not_for_severity_up(
    tmp_path: Path,
) -> None:
    refused(
        tmp_path,
        f"rules:\n  {R_STRUCTURING}:\n    mode: observe_only\n",
        r"rules\[CIAD-2026-0058\.R2\.structuring\]\.mode",
    )
    refused(
        tmp_path,
        f"rules:\n  {R_STRUCTURING}:\n    enabled: false\n",
        r"rules\[CIAD-2026-0058\.R2\.structuring\]\.enabled",
    )
    allowed = load(
        tmp_path,
        f"loosen: ['rules[*].mode']\nrules:\n  {R_STRUCTURING}:\n    mode: observe_only\n"
        f"  {R_VELOCITY}:\n    severity: critical\n",
    )
    assert allowed.rules[R_STRUCTURING].mode is Mode.OBSERVE_ONLY
    assert allowed.rules[R_VELOCITY].severity == "critical"


# --------------------------------------------------------------------------------------
# Exemptions
# --------------------------------------------------------------------------------------

NOW = datetime(2026, 11, 11, 5, 30, tzinfo=UTC)


def exemption(**kw: Any) -> Exemption:
    params: dict[str, Any] = {
        "id": "ex-1",
        "rules": frozenset({R_NEW_BENEFICIARY}),
        "reason": "Quarterly vendor onboarding, ticket RISK-123",
        "approved_by": "risk-officer@bank",
        "starts_at": NOW - timedelta(days=5),
        "expires_at": NOW + timedelta(days=20),
        "match": ExemptionMatch(tools=frozenset({TOOL}), beneficiaries=frozenset({"acct-v"})),
    }
    params.update(kw)
    return Exemption(**params)


def test_exemption_model_rules() -> None:
    with pytest.raises(ValidationError, match="at least one of tools"):
        ExemptionMatch()
    with pytest.raises(ValidationError, match="only waive step-up rules"):
        exemption(rules=frozenset({R_STRUCTURING}))
    with pytest.raises(ValidationError, match="only waive step-up rules"):
        exemption(rules=frozenset({R_VELOCITY, R_HITL}))
    with pytest.raises(ValidationError, match="expires_at must be after"):
        exemption(expires_at=NOW - timedelta(days=9))
    with pytest.raises(ValidationError):
        exemption(reason="too short")
    with pytest.raises(ValidationError):
        exemption(starts_at=datetime(2026, 1, 1))  # naive datetime
    with pytest.raises(ValidationError):
        exemption(rules=frozenset())
    assert exemption(
        match=ExemptionMatch(beneficiaries=frozenset({"ACCT@Bank"}))
    ).match.beneficiaries == {"acct@bank"}


def test_policy_limits_exemption_duration_and_ids() -> None:
    long_one = exemption(expires_at=NOW + timedelta(days=200))
    with pytest.raises(ValidationError, match="longer than exemption_max_days"):
        PolicyConfig(exemptions=(long_one,))
    assert PolicyConfig(exemptions=(long_one,), exemption_max_days=365).exemptions
    with pytest.raises(ValidationError, match="duplicate exemption id"):
        PolicyConfig(exemptions=(exemption(), exemption()))
    with pytest.raises(ValidationError):
        PolicyConfig(exemption_max_days=0)


def shield_with(make_shield: Callable[..., Shield], *ex: Exemption, **kw: Any) -> Shield:
    return make_shield(exemptions=tuple(ex), **kw)


def test_exemption_waives_a_step_up_and_is_reported(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh = shield_with(make_shield, exemption())
    ev = sh.evaluate(pay(mint("run-1"), amount="2500", beneficiary="acct-v"))
    assert ev.decision is Decision.ALLOW and ev.approval_request is None
    [note] = [f for f in ev.findings if f.rule_id == R_EXEMPTION_APPLIED]
    assert note.decision is Decision.ALLOW
    for needle in ("ex-1", R_NEW_BENEFICIARY, "risk-officer@bank", "RISK-123", "2026-12-01"):
        assert needle in note.detail


@pytest.mark.parametrize(
    "call",
    [
        {"beneficiary": "acct-other"},  # payee not listed
        {"beneficiary": "acct-v", "beneficiaries": ("acct-v", "acct-x")},  # one extra payee
        {"beneficiary": "acct-v", "tool": "initiate_disbursement"},  # tool not listed
        {"beneficiary": "acct-v", "sub": "someone-else"},  # subject not listed
        {"beneficiary": "acct-v", "env": Env.STAGING},  # environment not listed
        {},  # no payee at all
    ],
)
def test_exemption_does_not_apply_outside_its_match(
    call: dict[str, Any], make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    ex = exemption(
        match=ExemptionMatch(
            tools=frozenset({TOOL}),
            beneficiaries=frozenset({"acct-v"}),
            subjects=frozenset({"svc"}),
            envs=frozenset({Env.PROD}),
        )
    )
    sh = shield_with(make_shield, ex)
    env = call.get("env", Env.PROD)
    token = mint("run-1", call.get("sub", "svc"), env)
    ctx = pay(
        token,
        amount="2500",
        beneficiary=call.get("beneficiary"),
        beneficiaries=call.get("beneficiaries", ()),
        tool=call.get("tool", TOOL),
        env=env,
    )
    ev = sh.evaluate(ctx)
    assert not any(f.rule_id == R_EXEMPTION_APPLIED for f in ev.findings)


def test_exemption_window_is_enforced_by_the_shield_clock(
    make_shield: Callable[..., Shield], mint: Callable[..., str], clock: FakeClock
) -> None:
    sh = shield_with(
        make_shield,
        exemption(starts_at=NOW + timedelta(days=1), expires_at=NOW + timedelta(days=3)),
    )

    def attempt(run: str) -> Evaluation:
        return sh.evaluate(pay(mint(run), run, "2500", beneficiary="acct-v"))

    def waived(ev: Evaluation) -> bool:
        return any(f.rule_id == R_EXEMPTION_APPLIED for f in ev.findings)

    not_started = attempt("run-1")
    assert not waived(not_started) and not_started.decision is Decision.HITL_REQUIRED
    clock.advance(86_400 * 2)  # whole days keep the same local time of day (business hours)
    inside = attempt("run-2")
    assert waived(inside) and inside.decision is Decision.ALLOW
    clock.advance(86_400 * 2)  # past expires_at
    expired = attempt("run-3")
    assert not waived(expired)
    assert any(f.rule_id == R_NEW_BENEFICIARY for f in expired.findings)


def test_an_expired_exemption_warns_at_startup(
    make_shield: Callable[..., Shield], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        shield_with(make_shield, exemption(expires_at=NOW - timedelta(days=1)))
    assert "exemption 'ex-1' expired" in caplog.text


def test_an_exemption_never_waives_a_block(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    nb = PolicyConfig.from_yaml(PRESET).new_beneficiary.model_copy(update={"action": "block"})
    sh = shield_with(make_shield, exemption(), new_beneficiary=nb)
    ev = sh.evaluate(pay(mint("run-1"), amount="2500", beneficiary="acct-v"))
    assert ev.decision is Decision.BLOCK
    assert not any(f.rule_id == R_EXEMPTION_APPLIED for f in ev.findings)


def test_exemption_waives_the_high_value_and_off_hours_gates_and_the_cap(
    make_shield: Callable[..., Shield], mint: Callable[..., str], clock: FakeClock
) -> None:
    blanket = exemption(
        rules=frozenset({R_HITL, R_OFF_HOURS_HITL, R_NEW_BENEFICIARY, R_CUMULATIVE_CAP}),
        match=ExemptionMatch(tools=frozenset({TOOL})),
    )
    base = PolicyConfig.from_yaml(PRESET)
    sh = shield_with(
        make_shield,
        blanket,
        structuring=base.structuring.model_copy(update={"enabled": False}),
        cumulative_cap=CumulativeCapPolicy(
            enabled=True, protected_tools=frozenset({TOOL}), per_run={"USD": Decimal("1000")}
        ),
    )
    ev = sh.evaluate(pay(mint("run-1"), amount="15000", beneficiary="acct-1"))  # all gates fire
    assert ev.decision is Decision.ALLOW
    note = next(f for f in ev.findings if f.rule_id == R_EXEMPTION_APPLIED)
    for rule in (R_HITL, R_NEW_BENEFICIARY, R_CUMULATIVE_CAP):
        assert rule in note.detail
    # the exempt payment still counts toward the cap
    again = sh.evaluate(pay(mint("run-1"), amount="1", beneficiary="acct-1"))
    assert again.decision is Decision.ALLOW

    clock.wall = WEEKEND_UTC  # mandatory off-hours HITL is waived too
    clock.mono += 1000
    weekend = sh.evaluate(pay(mint("run-2"), "run-2", amount="10", beneficiary="acct-1"))
    assert weekend.decision is Decision.ALLOW
    assert (
        R_OFF_HOURS_HITL
        in next(f for f in weekend.findings if f.rule_id == R_EXEMPTION_APPLIED).detail
    )


def test_exemption_use_is_written_to_the_audit_log(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh = shield_with(make_shield, exemption())
    guarded = sh.guard(_paid)
    assert guarded(ctx=pay(mint("run-1"), amount="2500", beneficiary="acct-v")) == "paid"
    sh.close()
    assert R_EXEMPTION_APPLIED in Path(sh.policy.audit_path).read_text(encoding="utf-8")


def test_concurrent_calls_all_see_the_exemption(
    make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    sh = shield_with(make_shield, exemption())
    results: list[Decision] = []
    barrier = threading.Barrier(6)

    def worker(i: int) -> None:
        run = f"run-{i}"
        ctx = pay(mint(run, f"svc-{i}"), run, "1500", beneficiary="acct-v")
        barrier.wait()
        results.append(sh.evaluate(ctx).decision)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [Decision.ALLOW] * 6


def test_exemption_in_an_overlay_is_a_loosening_and_works_end_to_end(
    tmp_path: Path, make_shield: Callable[..., Shield], mint: Callable[..., str]
) -> None:
    body = (
        "exemptions:\n"
        "  - id: ex-1\n"
        f"    rules: [{R_NEW_BENEFICIARY}]\n"
        "    reason: Quarterly vendor onboarding, ticket RISK-123\n"
        "    approved_by: risk-officer@bank\n"
        "    starts_at: 2026-11-01T00:00:00Z\n"
        "    expires_at: 2026-12-01T00:00:00Z\n"
        "    match: {tools: [settle_merchant], beneficiaries: [acct-v]}\n"
    )
    refused(tmp_path, body, r"exemptions\[ex-1\]")
    policy = load(tmp_path, "loosen: ['exemptions[ex-1]']\n" + body)
    assert policy.provenance is not None
    assert any(item.startswith("exemptions[ex-1]") for item in policy.provenance.loosened)
    sh = make_shield(exemptions=policy.exemptions)
    ev = sh.evaluate(pay(mint("run-1"), amount="2500", beneficiary="acct-v"))
    assert ev.decision is Decision.ALLOW


def test_gateway_cli_style_loading_and_show_policy_print_provenance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = overlay(tmp_path, "hitl:\n  thresholds: {USD: '5000'}\n")
    assert main(["show-policy", str(path)]) == 0
    out = capsys.readouterr().out
    assert '"provenance"' in out and "overlay.yaml@sha256:" in out
    assert (
        main(["show-policy", str(overlay(tmp_path, "hitl:\n  thresholds: {USD: '99999'}\n"))]) == 2
    )
    assert "loosens the base policy" in capsys.readouterr().err


def test_the_documented_example_overlay_loads_and_records_every_loosening() -> None:
    example = Path(__file__).resolve().parent.parent / "examples" / "acme_overlay.yaml"
    policy = load_policy(example)
    assert policy.hitl.thresholds["USD"] == Decimal("7500")
    assert "pay_vendor" in policy.structuring.protected_tools
    assert policy.rules[R_SEQUENCE].mode is Mode.OBSERVE_ONLY
    assert [e.id for e in policy.exemptions] == ["onboarding-batch-q4"]
    assert policy.provenance is not None
    assert len(policy.provenance.loosened) == 3
