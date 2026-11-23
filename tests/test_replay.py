"""Phase 4: the replay corpus and its harness.

Rationale: "the preset stops the attack" has to be a number someone can reproduce. The corpus is a
versioned set of synthetic traces, the harness replays them through the real shield, and the
tests below check three things: the corpus is what its generator says, the numbers are right, and
(the part that matters most) the harness can *fail*: weaken a rule and the right scenarios break.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from redhand_fintech_shield import Mode, PolicyConfig, RuleOverride, __version__, load_policy
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.replay import (
    ALL_TOOLS,
    INPUT_REJECTED,
    START,
    Corpus,
    CorpusError,
    ReplayHarness,
    ReplayReport,
    ReplayStep,
    Scenario,
    default_corpus_dir,
    load_corpus,
    render_markdown,
    run_corpus,
)
from redhand_fintech_shield.rules import (
    R_APPROVAL_REJECTED,
    R_CUMULATIVE_CAP,
    R_ENV_PIVOT,
    R_HITL,
    R_MICRO_TX,
    R_NEW_BENEFICIARY,
    R_OFF_HOURS_HITL,
    R_QUARANTINED,
    R_SEQUENCE,
    R_STRUCTURING,
    R_TOKEN_INVALID,
    R_TOOL_NOT_PINNED,
    R_VELOCITY,
    RULE_CATALOG,
)

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location("corpus_generate", CORPUS_DIR / "generate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["corpus_generate"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return load_corpus(CORPUS_DIR)


@pytest.fixture(scope="module")
def policy(corpus: Corpus) -> PolicyConfig:
    return load_policy(corpus.policy_path)


@pytest.fixture(scope="module")
def report(corpus: Corpus, policy: PolicyConfig) -> ReplayReport:
    return run_corpus(corpus, policy, __version__)


def failing_ids(corpus: Corpus, policy: PolicyConfig) -> set[str]:
    harness = ReplayHarness(policy)
    return {s.id for s in corpus.scenarios if not harness.run(s).ok}


# --------------------------------------------------------------------------------------
# The corpus is what its generator says, and is internally consistent
# --------------------------------------------------------------------------------------


def test_the_committed_corpus_is_what_the_generator_produces() -> None:
    generator = _generator()
    assert (CORPUS_DIR / "scenarios.jsonl").read_text(encoding="utf-8") == generator.render(), (
        "corpus/scenarios.jsonl is out of date: run `python corpus/generate.py` and bump "
        "CORPUS_VERSION in the generator if scenarios changed"
    )


def test_the_corpus_is_consistent(corpus: Corpus) -> None:
    assert corpus.header.corpus_version == _generator().CORPUS_VERSION
    ids = [s.id for s in corpus.scenarios]
    assert len(ids) == len(set(ids)) and len(ids) >= 100
    for s in corpus.scenarios:
        calls = [st for st in s.steps if st.action == "call"]
        assert calls, s.id
        assert all(st.tool in ALL_TOOLS for st in calls), f"{s.id}: a step names an unknown tool"
        assert s.start in START
        if s.label == "attack" and not s.known_gap:
            assert s.expect_rules, s.id
        if s.known_gap:
            assert not s.expect_rules and all(st.expect in (None, "allow") for st in s.steps), s.id
        if s.known_false_positive:
            assert any(st.expect not in (None, "allow") for st in s.steps), s.id


def test_every_rule_that_can_stop_a_call_is_exercised_by_an_attack(corpus: Corpus) -> None:
    exercised = {r for s in corpus.scenarios if not s.known_gap for r in s.expect_rules}
    stoppers = {r.id for r in RULE_CATALOG if r.decision != "allow"}
    assert stoppers <= exercised, f"no attack exercises: {sorted(stoppers - exercised)}"
    assert INPUT_REJECTED in exercised  # input refused before any rule runs is a stop too


def test_the_corpus_covers_the_bypasses_the_roadmap_names(corpus: Corpus) -> None:
    ids = {s.id for s in corpus.scenarios}
    assert {"A-struct-06", "A-struct-03", "A-struct-05"} <= ids  # currency, run and spelling splits
    assert {"A-rotate-01", "A-rotate-02"} <= ids  # tool rotation
    assert {"A-args-01", "A-args-02", "G-unbound"} <= ids  # renamed arguments, bound and unbound
    assert {"A-bulk-01", "A-bulk-02", "A-bulk-03", "A-bulk-04", "A-bulk-05"} <= ids  # bulk lists
    assert {"G-probe-first", "G-lowslow", "G-stolen", "G-justunder"} <= ids  # honest limits


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def write_corpus(tmp_path: Path, *scenario_lines: str, header: str | None = None) -> Path:
    head = header or json.dumps(
        {"type": "header", "corpus_version": "9.9.9", "description": "t", "policy": "policy.yaml"}
    )
    (tmp_path / "scenarios.jsonl").write_text(
        "\n".join([head, *scenario_lines]) + "\n", encoding="utf-8"
    )
    (tmp_path / "policy.yaml").write_text("extends: certin_ciad_2026_0058\n", encoding="utf-8")
    return tmp_path


def line(**kw: Any) -> str:
    base: dict[str, Any] = {
        "id": "S-1",
        "label": "benign",
        "category": "c",
        "summary": "s",
        "steps": [{"tool": "charge_card", "args": {"amount": "100", "currency": "USD"}}],
    }
    base.update(kw)
    return json.dumps(base)


def test_a_minimal_corpus_loads_and_runs(tmp_path: Path) -> None:
    loaded = load_corpus(write_corpus(tmp_path, line()))
    assert loaded.header.corpus_version == "9.9.9" and len(loaded.scenarios) == 1
    assert len(loaded.sha256) == 64


@pytest.mark.parametrize(
    ("lines", "message"),
    [
        ([line(id="S-1"), line(id="S-1")], "duplicate scenario ids"),
        ([line(known_gap="x")], "known_gap only makes sense on an attack"),
        (
            [line(label="attack", known_false_positive="x", expect_rules=["r"])],
            "known_false_positive only",
        ),
        ([line(label="attack")], "must name the rules"),
        (["{not json"], "cannot load corpus"),
        ([line(surprise=1)], "cannot load corpus"),
        ([line(steps=[{"tool": "t", "at": -1}])], "cannot load corpus"),
        ([line(steps=[{"tool": "t", "token_mode": "magic"}])], "cannot load corpus"),
        ([line(start="midnight")], "cannot load corpus"),
    ],
)
def test_a_malformed_corpus_is_refused(tmp_path: Path, lines: list[str], message: str) -> None:
    with pytest.raises(CorpusError, match=message):
        load_corpus(write_corpus(tmp_path, *lines))


def test_a_missing_or_empty_corpus_is_refused(tmp_path: Path) -> None:
    with pytest.raises(CorpusError, match="cannot load corpus"):
        load_corpus(tmp_path)
    (tmp_path / "scenarios.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(CorpusError, match="cannot load corpus"):
        load_corpus(tmp_path)


def test_models_reject_unknown_fields_and_bad_values() -> None:
    with pytest.raises(ValidationError):
        ReplayStep(surprise=1)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Scenario(id="x", label="maybe", category="c", summary="s", steps=())  # type: ignore[arg-type]


def test_the_corpus_ships_in_the_wheel() -> None:
    import tomllib

    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    shared = meta["tool"]["hatch"]["build"]["targets"]["wheel"]["shared-data"]
    assert shared["corpus"] == "share/redhand-certin-0058-preset/corpus"


def test_default_corpus_dir_checks_the_checkout_then_the_installed_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from redhand_fintech_shield import replay as replay_module

    assert default_corpus_dir() == CORPUS_DIR
    monkeypatch.setattr(replay_module, "__file__", str(tmp_path / "a" / "b" / "replay.py"))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "prefix"))
    with pytest.raises(CorpusError, match="bundled corpus not found"):
        default_corpus_dir()
    shared = tmp_path / "prefix" / "share" / "redhand-certin-0058-preset" / "corpus"
    shared.mkdir(parents=True)
    (shared / "scenarios.jsonl").write_text("{}\n", encoding="utf-8")
    assert default_corpus_dir() == shared


# --------------------------------------------------------------------------------------
# The numbers
# --------------------------------------------------------------------------------------


def test_every_scenario_behaves_as_the_corpus_says(report: ReplayReport) -> None:
    assert report.failures == (), report.failures


def test_the_headline_numbers(report: ReplayReport, corpus: Corpus) -> None:
    gaps = sum(1 for s in corpus.scenarios if s.known_gap)
    assert report.scenarios == len(corpus.scenarios) == 108
    assert report.attacks == report.attacks_detectable + gaps
    assert (report.attacks_detectable, report.attacks_stopped) == (73, 73)
    assert report.detection_rate == 1.0 and report.payoff_stop_rate == 1.0
    assert len(report.known_gaps) == gaps == 5
    assert (report.benign_checked, report.benign_flagged) == (26, 0)
    assert report.false_positive_rate == 0.0 and report.benign_steps_flagged == 0
    assert len(report.documented_false_positives) == 4


def test_per_rule_numbers_are_internally_consistent(report: ReplayReport) -> None:
    by_rule = {r.rule: r for r in report.per_rule}
    for rule in (R_STRUCTURING, R_HITL, R_NEW_BENEFICIARY, R_MICRO_TX, R_VELOCITY, R_SEQUENCE):
        row = by_rule[rule]
        assert row.attacks_expecting >= 2 and row.attacks_detected == row.attacks_expecting
        assert row.recall == 1.0 and row.false_positive_rate == 0.0
    # the documented false positives are attributed to the rules that cause them
    assert by_rule[R_MICRO_TX].documented_false_positives >= 2
    assert by_rule[R_VELOCITY].documented_false_positives >= 1
    assert by_rule[R_OFF_HOURS_HITL].documented_false_positives >= 1
    assert {
        R_ENV_PIVOT,
        R_TOKEN_INVALID,
        R_TOOL_NOT_PINNED,
        R_CUMULATIVE_CAP,
        R_QUARANTINED,
        R_APPROVAL_REJECTED,
        INPUT_REJECTED,
    } <= set(by_rule)


def test_categories_add_up(report: ReplayReport) -> None:
    assert sum(c.attacks for c in report.per_category) == report.attacks_detectable
    assert sum(c.stopped for c in report.per_category) == report.attacks_stopped
    assert sum(c.benign for c in report.per_category) == report.benign
    assert {"stage 1: credential pivot", "split transactions", "slow drain", "token abuse"} <= {
        c.category for c in report.per_category
    }


def test_a_run_is_deterministic_apart_from_latency(
    corpus: Corpus, policy: PolicyConfig, report: ReplayReport
) -> None:
    again = run_corpus(corpus, policy, __version__)
    assert again.model_dump(exclude={"latency_ms"}) == report.model_dump(exclude={"latency_ms"})
    assert report.latency_ms["p99"] < 25.0  # a sanity bound, not a benchmark


def test_the_report_names_the_exact_corpus_and_policy(
    report: ReplayReport, corpus: Corpus, policy: PolicyConfig
) -> None:
    import hashlib

    assert (
        report.corpus_sha256
        == hashlib.sha256((CORPUS_DIR / "scenarios.jsonl").read_bytes()).hexdigest()
    )
    assert report.corpus_version == corpus.header.corpus_version
    assert report.policy_sha256 == policy.fingerprint()
    assert report.preset_version == policy.preset_version


def test_the_results_document_is_in_sync(report: ReplayReport) -> None:
    committed = (ROOT / "docs" / "detection-results.md").read_text(encoding="utf-8")
    assert committed == render_markdown(report), (
        "docs/detection-results.md is out of date: run "
        "`redhand-shield replay --markdown docs/detection-results.md`"
    )


def test_the_markdown_states_the_limits_beside_the_numbers(report: ReplayReport) -> None:
    text = render_markdown(report)
    assert (
        "The corpus is synthetic" in text and "regression check, not a security guarantee" in text
    )
    assert "## Documented gaps" in text and "G-probe-first" in text
    assert "## Documented false positives" in text and "FP-coffee" in text


# --------------------------------------------------------------------------------------
# The harness can fail (this is what makes the numbers mean something)
# --------------------------------------------------------------------------------------


def expecting(corpus: Corpus, rule: str) -> set[str]:
    return {s.id for s in corpus.scenarios if not s.known_gap and rule in s.expect_rules}


@pytest.mark.parametrize(
    "rule", [R_STRUCTURING, R_MICRO_TX, R_VELOCITY, R_SEQUENCE, R_CUMULATIVE_CAP]
)
def test_switching_a_rule_off_breaks_exactly_the_attacks_that_depend_on_it(
    corpus: Corpus, policy: PolicyConfig, rule: str
) -> None:
    weakened = policy.model_copy(update={"rules": {rule: RuleOverride(enabled=False)}})
    broken = failing_ids(corpus, weakened)
    assert expecting(corpus, rule) <= broken
    # nothing unrelated is disturbed: whatever else fails is documented behaviour of that rule
    extra = broken - expecting(corpus, rule)
    assert all(
        s.startswith(("FP-", "A-struct-10")) or s in expecting(corpus, rule) for s in extra
    ), extra


def test_a_rule_in_shadow_mode_is_not_a_detection(corpus: Corpus, policy: PolicyConfig) -> None:
    shadow = policy.model_copy(update={"rules": {R_HITL: RuleOverride(mode=Mode.OBSERVE_ONLY)}})
    assert expecting(corpus, R_HITL) <= failing_ids(corpus, shadow)


def test_loosening_thresholds_loses_attacks(corpus: Corpus, policy: PolicyConfig) -> None:
    loose = policy.model_copy(
        update={
            "hitl": policy.hitl.model_copy(
                update={"thresholds": {k: v * 100 for k, v in policy.hitl.thresholds.items()}}
            )
        }
    )
    broken = failing_ids(corpus, loose)
    assert {"A-hitl-01", "A-hitl-02", "A-hitl-05"} <= broken


def test_an_over_eager_rule_produces_false_positives(corpus: Corpus, policy: PolicyConfig) -> None:
    eager = policy.model_copy(
        update={
            "micro_tx": policy.micro_tx.model_copy(
                update={"ceilings": {k: v * 1000 for k, v in policy.micro_tx.ceilings.items()}}
            )
        }
    )
    harness = ReplayHarness(eager)
    flagged = [
        s.id
        for s in corpus.scenarios
        if s.label == "benign" and not s.known_false_positive and not harness.run(s).ok
    ]
    assert len(flagged) >= 5, flagged


def test_without_the_bindings_the_renamed_field_attacks_get_through(corpus: Corpus) -> None:
    """The bare preset binds none of the corpus payment tools; the corpus shows the cost."""
    bare = load_policy()
    broken = failing_ids(corpus, bare)
    assert {"A-args-01", "A-args-02", "A-bulk-01", "A-newben-04", "A-newben-05"} <= broken


def test_a_documented_gap_that_becomes_detected_fails_the_corpus(
    corpus: Corpus, policy: PolicyConfig
) -> None:
    stricter = policy.model_copy(
        update={
            "hitl": policy.hitl.model_copy(
                update={"thresholds": {**policy.hitl.thresholds, "USD": Decimal("5000")}}
            )
        }
    )
    harness = ReplayHarness(stricter)
    gap = next(s for s in corpus.scenarios if s.id == "G-justunder")
    result = harness.run(gap)
    assert not result.ok and "documented gap is now detected" in result.reasons[0]


def test_a_documented_false_positive_that_stops_firing_fails_the_corpus(
    corpus: Corpus, policy: PolicyConfig
) -> None:
    quiet = policy.model_copy(update={"rules": {R_MICRO_TX: RuleOverride(enabled=False)}})
    result = ReplayHarness(quiet).run(next(s for s in corpus.scenarios if s.id == "FP-coffee"))
    assert not result.ok and "expected block, got allow" in result.reasons[0]


# --------------------------------------------------------------------------------------
# Harness mechanics
# --------------------------------------------------------------------------------------


def run_one(policy: PolicyConfig, **kw: Any) -> Any:
    scenario = Scenario.model_validate(
        {"id": "T", "label": "benign", "category": "t", "summary": "t", **kw}
    )
    return ReplayHarness(policy).run(scenario)


def test_each_token_mode_is_refused_for_its_own_reason(policy: PolicyConfig) -> None:
    for mode in ("expired", "foreign_key", "alg_none", "tampered", "wrong_run"):
        result = run_one(
            policy,
            steps=[
                {
                    "tool": "charge_card",
                    "args": {"amount": "100", "currency": "USD"},
                    "token_mode": mode,
                    "expect": "block",
                }
            ],
        )
        assert result.ok and result.fired == {R_TOKEN_INVALID}, mode


def test_an_unusable_approval_step_is_a_plain_call_not_a_crash(policy: PolicyConfig) -> None:
    result = run_one(
        policy,
        steps=[
            {
                "tool": "settle_merchant",
                "args": {"amount": "100", "currency": "USD", "beneficiary": "acct-trusted-1"},
                "approval": "replay",
            }
        ],
    )
    assert result.outcomes[0].decision in {"allow", "hitl_required", "block"}


def test_a_scenario_with_no_calls_has_no_payoff(policy: PolicyConfig) -> None:
    result = run_one(
        policy,
        label="attack",
        expect_rules=["x"],
        known_gap="nothing happens",
        steps=[{"action": "revoke", "revoke": {"kind": "run", "value": "r"}}],
    )
    assert result.payoff_stopped is None and result.outcomes == ()


def test_the_harness_touches_no_files_and_leaves_the_policy_alone(
    policy: PolicyConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    harness = ReplayHarness(policy)
    assert harness.policy.quarantine_journal_path is None
    assert harness.policy.approval.nonce_journal_path is None
    run_one(policy, steps=[{"tool": "list_merchants"}])
    assert list(tmp_path.iterdir()) == []


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def test_replay_command_prints_numbers_and_writes_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    assert main(["replay", "--json", str(out_json), "--markdown", str(out_md)]) == 0
    printed = capsys.readouterr().out
    assert "attacks stopped 73/73" in printed and "benign flagged 0/26" in printed
    assert "CIAD-2026-0058.R2.structuring" in printed
    parsed = ReplayReport.model_validate_json(out_json.read_text(encoding="utf-8"))
    assert parsed.attacks_stopped == 73
    assert out_md.read_text(encoding="utf-8").startswith("# Detection results")


def test_replay_command_fails_when_a_scenario_misbehaves(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = line(
        id="X-1",
        label="attack",
        expect_rules=[R_STRUCTURING],
        steps=[{"tool": "charge_card", "args": {"amount": "100", "currency": "USD"}}],
    )
    assert main(["replay", "--corpus", str(write_corpus(tmp_path, broken))]) == 1
    assert "FAIL X-1" in capsys.readouterr().err


def test_replay_command_reports_an_unreadable_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["replay", "--corpus", str(tmp_path)]) == 2
    assert "cannot load corpus" in capsys.readouterr().err
