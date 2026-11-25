"""Replay a corpus of attack and benign traces through the shield and measure it.

A *scenario* is a short trace of tool calls (an attack in the shape of the CRAFTY FALCON chain, or
ordinary traffic). The harness runs each one through a fresh :class:`~redhand_fintech_shield.Shield`
on a fake clock, using the same extraction and bindings as the gateway, and records what the shield
decided. From that it reports, per rule, the detection rate on attacks that should trip it and the
false-positive rate on benign traffic, and it fails loudly when any scenario does not behave as the
corpus says it should.

The corpus is **synthetic**: scenarios are written to exercise rules, not sampled from real
traffic, so the numbers measure whether each control does what it claims on the cases we thought
of, not how it would perform in production. Cases the preset is documented *not* to catch are kept
in the corpus (``known_gap``) and benign cases it documented-ly flags are kept too
(``known_false_positive``), so the limits sit beside the numbers.
"""

# ruff: noqa: S105 - `token_mode` names a test-scenario mode; it is not a credential

from __future__ import annotations

import base64
import hashlib
import json
import logging
import statistics
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .approvals import ApprovalIssuer, ApprovalVerifier
from .context import extract_tool_call_context
from .crypto import AgentTokenIssuer, AgentTokenVerifier
from .detectors import QuarantineRegistry
from .exceptions import PolicyLoadError
from .interceptor import Shield
from .models import ApprovalRequest, Decision, Env, PolicyConfig
from .protocols import NullAuditLog
from .revocations import RevocationRegistry

_STRICT = ConfigDict(frozen=True, extra="forbid")

#: Pseudo rule id for input that was refused before any rule ran (a negative bulk element, a
#: float amount, a non-finite number): the call never reaches evaluation, which is also a stop.
INPUT_REJECTED = "extraction.input_rejected"

ALL_TOOLS = (
    "list_merchants",
    "get_account",
    "list_beneficiaries",
    "charge_card",
    "settle_merchant",
    "initiate_disbursement",
    "bulk_payout",
    "pay_vendor",
    "upi_send",
    "bulk_transfer",
    "transfer_funds",
)
START = {
    "business": datetime(2026, 11, 11, 5, 30, tzinfo=UTC),  # Wednesday 11:00 IST
    "weekend": datetime(2026, 11, 14, 5, 30, tzinfo=UTC),  # Saturday 11:00 IST
    "night": datetime(2026, 11, 11, 19, 30, tzinfo=UTC),  # 01:00 IST
    "holiday": datetime(2026, 12, 25, 5, 30, tzinfo=UTC),  # Christmas Day, a Friday, 11:00 IST
}


class CorpusError(PolicyLoadError):
    """The corpus is missing, malformed or inconsistent."""


# --------------------------------------------------------------------------------------
# Corpus format
# --------------------------------------------------------------------------------------


class ReplayStep(BaseModel):
    """One tool call (or one operator action) in a scenario."""

    model_config = _STRICT

    at: float = Field(default=0.0, ge=0, description="Seconds after the scenario starts.")
    action: Literal["call", "revoke"] = "call"
    run: str = "run"
    subject: str = "svc-agent"
    tool: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    token_env: Env = Env.PROD
    target_env: Env = Env.PROD
    token_mode: Literal["valid", "expired", "foreign_key", "alg_none", "tampered", "wrong_run"] = (
        "valid"
    )
    allowed_tools: tuple[str, ...] | None = None
    hitl_step_up: bool = False
    approval: Literal["grant", "replay", "mismatched", "forged"] | None = None
    revoke: dict[str, str] | None = None
    expect: Decision | None = Field(
        default=None, description="The decision the corpus expects for this step."
    )


class Scenario(BaseModel):
    """A trace with a verdict: what it is, and what the shield should do with it."""

    model_config = _STRICT

    id: str
    label: Literal["attack", "benign"]
    category: str
    summary: str
    start: Literal["business", "weekend", "night", "holiday"] = "business"
    steps: tuple[ReplayStep, ...]
    expect_rules: tuple[str, ...] = Field(
        default=(), description="Rules that must fire (enforced, non-allow) somewhere in an attack."
    )
    payoff_step: int | None = Field(
        default=None, description="Index of the money-moving step (default: the last call)."
    )
    known_gap: str | None = Field(
        default=None, description="An attack the preset is documented NOT to detect, and why."
    )
    known_false_positive: str | None = Field(
        default=None, description="Benign traffic the preset is documented to flag, and why."
    )


class CorpusHeader(BaseModel):
    model_config = _STRICT

    type: Literal["header"] = "header"
    corpus_version: str
    description: str
    policy: str = "policy.yaml"
    seed: int = 0


@dataclass(frozen=True, slots=True)
class Corpus:
    header: CorpusHeader
    scenarios: tuple[Scenario, ...]
    sha256: str  # of the scenarios file, so results name the exact corpus they came from
    policy_path: Path


def default_corpus_dir() -> Path:
    """The bundled corpus (repo checkout first, then an installed wheel's shared data)."""
    candidates = [
        Path(__file__).resolve().parents[2] / "corpus",
        Path(sys.prefix) / "share" / "redhand-certin-0058-preset" / "corpus",
    ]
    for candidate in candidates:
        if (candidate / "scenarios.jsonl").is_file():
            return candidate
    raise CorpusError("bundled corpus not found; pass --corpus DIR")


def load_corpus(directory: Path | None = None) -> Corpus:
    root = directory if directory is not None else default_corpus_dir()
    path = root / "scenarios.jsonl"
    try:
        blob = path.read_bytes()
        lines = [ln for ln in blob.decode("utf-8").splitlines() if ln.strip()]
        header = CorpusHeader.model_validate(json.loads(lines[0]))
        scenarios = tuple(Scenario.model_validate(json.loads(ln)) for ln in lines[1:])
    except (OSError, ValueError, IndexError, ValidationError) as exc:
        raise CorpusError(f"cannot load corpus {path}: {exc}") from exc
    ids = [s.id for s in scenarios]
    if len(ids) != len(set(ids)):
        raise CorpusError(f"corpus {path} has duplicate scenario ids")
    for s in scenarios:
        if s.known_gap and s.label != "attack":
            raise CorpusError(f"{s.id}: known_gap only makes sense on an attack")
        if s.known_false_positive and s.label != "benign":
            raise CorpusError(f"{s.id}: known_false_positive only makes sense on benign traffic")
        if s.label == "attack" and not s.known_gap and not s.expect_rules:
            raise CorpusError(f"{s.id}: an attack must name the rules that should catch it")
    return Corpus(header, scenarios, hashlib.sha256(blob).hexdigest(), root / header.policy)


# --------------------------------------------------------------------------------------
# Running scenarios
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StepOutcome:
    index: int
    decision: str
    rules: tuple[str, ...]  # rules that produced a non-allow finding on this step
    expected: str | None
    approval_requested: bool = False


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario: Scenario
    outcomes: tuple[StepOutcome, ...]
    ok: bool
    reasons: tuple[str, ...]
    fired: frozenset[str]
    payoff_stopped: bool | None
    unexpected: frozenset[str] = frozenset()  # rules that flagged a step the corpus expected clean
    latencies_ms: tuple[float, ...] = field(default=(), compare=False)


class _Clock:
    def __init__(self, start: datetime) -> None:
        self.start = start
        self.wall = start

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return 1000.0 + (self.wall - self.start).total_seconds()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class ReplayHarness:
    """Runs scenarios against ``policy`` with throwaway keys and in-memory state."""

    def __init__(self, policy: PolicyConfig) -> None:
        self._token_key = Ed25519PrivateKey.generate()
        self._approver_key = Ed25519PrivateKey.generate()
        self._foreign_key = Ed25519PrivateKey.generate()
        # nothing touches disk: journals and the audit log are off, state is in memory
        self.policy = policy.model_copy(
            update={
                "quarantine_journal_path": None,
                "revocation_journal_path": None,
                "approval": policy.approval.model_copy(update={"nonce_journal_path": None}),
            }
        )

    def _shield(self, clock: _Clock) -> Shield:
        verifier = AgentTokenVerifier(
            self._token_key.public_key(),
            self.policy.issuer,
            max_ttl_seconds=self.policy.max_token_ttl_seconds,
            clock=clock.now,
        )
        return Shield(
            self.policy,
            verifier,
            audit=NullAuditLog(),
            quarantine=QuarantineRegistry(None),
            revocations=RevocationRegistry(None, clock=clock.now),
            approval_verifier=ApprovalVerifier(
                self._approver_key.public_key(),
                self.policy.approval.issuer,
                max_ttl_seconds=self.policy.approval.max_ttl_seconds,
                clock=clock.now,
            ),
            clock=clock.now,
            monotonic=clock.monotonic,
        )

    def _token(self, step: ReplayStep, clock: _Clock) -> str:
        env = step.token_env
        common: dict[str, Any] = {
            "subject": step.subject,
            "agent_run_id": step.run + ("-other" if step.token_mode == "wrong_run" else ""),
            "env": env,
            "allowed_tools": step.allowed_tools or ALL_TOOLS,
            "hitl_step_up": step.hitl_step_up,
            "now": clock.now(),
        }
        issuer = AgentTokenIssuer(self._token_key, self.policy.issuer)
        match step.token_mode:
            case "expired":
                return issuer.mint(
                    **{**common, "now": clock.now() - timedelta(hours=2)}, ttl_seconds=60
                )
            case "foreign_key":
                return AgentTokenIssuer(self._foreign_key, self.policy.issuer).mint(**common)
            case "alg_none":
                good = issuer.mint(**common)
                header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
                return f"{header}.{good.split('.')[1]}."
            case "tampered":
                # minted for another environment, then the claim is edited and the signature kept
                good = issuer.mint(**{**common, "env": Env.STAGING})
                head, body, sig = good.split(".")
                claims = json.loads(_unb64(body))
                claims["env"] = env.value
                return f"{head}.{_b64(json.dumps(claims).encode())}.{sig}"
            case _:
                return issuer.mint(**common)

    def run(self, scenario: Scenario) -> ScenarioResult:
        clock = _Clock(START[scenario.start])
        shield = self._shield(clock)
        outcomes: list[StepOutcome] = []
        latencies: list[float] = []
        last_request: ApprovalRequest | None = None
        last_grant: str | None = None
        approver = ApprovalIssuer(self._approver_key, self.policy.approval.issuer)
        foreign = ApprovalIssuer(self._foreign_key, self.policy.approval.issuer)
        try:
            for index, step in enumerate(scenario.steps):
                clock.wall = clock.start + timedelta(seconds=step.at)
                if step.action == "revoke":
                    spec = step.revoke or {}
                    shield.revocations.revoke(
                        spec["kind"],  # type: ignore[arg-type]
                        spec["value"],
                        spec.get("reason", "corpus"),
                    )
                    continue
                args = {
                    **step.args,
                    "token": self._token(step, clock),
                    "agent_run_id": step.run,
                    "target_env": step.target_env.value,
                }
                if step.approval is not None and last_request is not None:
                    if step.approval == "grant":
                        last_grant = approver.grant(
                            last_request, approver="corpus-approver", now=clock.now()
                        )
                        args["approval"] = last_grant
                    elif step.approval == "replay" and last_grant is not None:
                        args["approval"] = last_grant
                    elif step.approval == "mismatched":
                        bumped = last_request.model_copy(
                            update={"amount": (last_request.amount or Decimal(0)) + 1}
                        )
                        args["approval"] = approver.grant(
                            bumped, approver="corpus-approver", now=clock.now()
                        )
                    elif step.approval == "forged":
                        args["approval"] = foreign.grant(
                            last_request, approver="mallory", now=clock.now()
                        )
                started = time.perf_counter()
                try:
                    ctx = extract_tool_call_context(
                        step.tool or "",
                        args,
                        default_env=step.target_env,
                        bindings=shield.policy.tool_bindings,
                    )
                except ValueError:
                    outcomes.append(
                        StepOutcome(index, Decision.BLOCK.value, (INPUT_REJECTED,), _exp(step))
                    )
                    continue
                evaluation = shield.evaluate(ctx)
                latencies.append((time.perf_counter() - started) * 1000.0)
                if evaluation.approval_request is not None:
                    last_request = evaluation.approval_request
                rules = tuple(
                    dict.fromkeys(
                        f.rule_id
                        for f in evaluation.findings
                        if f.decision is not Decision.ALLOW and f.enforced
                    )
                )
                outcomes.append(
                    StepOutcome(
                        index,
                        evaluation.decision.value,
                        rules,
                        _exp(step),
                        evaluation.approval_request is not None,
                    )
                )
        finally:
            shield.close()
        return _judge(scenario, tuple(outcomes), tuple(latencies))


def _exp(step: ReplayStep) -> str | None:
    return step.expect.value if step.expect is not None else None


def _judge(
    scenario: Scenario, outcomes: tuple[StepOutcome, ...], latencies: tuple[float, ...]
) -> ScenarioResult:
    fired = frozenset(r for o in outcomes for r in o.rules)
    calls = [i for i, s in enumerate(scenario.steps) if s.action == "call"]
    payoff_index = (
        scenario.payoff_step if scenario.payoff_step is not None else (calls[-1] if calls else None)
    )
    by_index = {o.index: o for o in outcomes}
    payoff = by_index.get(payoff_index) if payoff_index is not None else None
    payoff_stopped = None if payoff is None else payoff.decision != Decision.ALLOW.value
    reasons: list[str] = []
    unexpected: set[str] = set()

    for o in outcomes:
        want = o.expected or (Decision.ALLOW.value if scenario.label == "benign" else None)
        if want is not None and o.decision != want:
            got = ", ".join(o.rules) or "no rule"
            reasons.append(f"step {o.index}: expected {want}, got {o.decision} ({got})")
            if scenario.label == "benign":
                unexpected.update(o.rules)

    if scenario.label == "attack":
        if scenario.known_gap:
            if any(o.decision != Decision.ALLOW.value for o in outcomes):
                reasons.append("documented gap is now detected: update the corpus")
        else:
            missing = sorted(set(scenario.expect_rules) - fired)
            if missing:
                reasons.append(f"rules that should have fired did not: {', '.join(missing)}")
    return ScenarioResult(
        scenario,
        outcomes,
        not reasons,
        tuple(reasons),
        fired,
        payoff_stopped,
        frozenset(unexpected),
        latencies,
    )


# --------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------


class RuleStats(BaseModel):
    model_config = _STRICT

    rule: str
    attacks_expecting: int = 0
    attacks_detected: int = 0
    recall: float | None = None
    benign_scenarios_flagged: int = 0  # unexpected flags on benign traffic, per scenario
    false_positive_rate: float = 0.0
    documented_false_positives: int = 0  # benign traffic this rule is documented to flag


class CategoryStats(BaseModel):
    model_config = _STRICT

    category: str
    attacks: int
    stopped: int  # every expected rule fired
    payoff_stopped: int  # the money-moving step was not allowed
    benign: int = 0


class ReplayReport(BaseModel):
    """The measured result of one corpus run; everything but ``latency_ms`` is deterministic."""

    model_config = _STRICT

    corpus_version: str
    corpus_sha256: str
    package_version: str
    preset_version: str | None
    policy_sha256: str
    scenarios: int
    attacks: int
    attacks_detectable: int
    attacks_stopped: int
    detection_rate: float
    payoff_stop_rate: float
    known_gaps: tuple[str, ...]
    benign: int
    benign_checked: int
    benign_flagged: int
    false_positive_rate: float
    benign_steps: int
    benign_steps_flagged: int
    documented_false_positives: tuple[str, ...]
    per_rule: tuple[RuleStats, ...]
    per_category: tuple[CategoryStats, ...]
    failures: tuple[str, ...]
    latency_ms: dict[str, float] = Field(default_factory=dict)


def _ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def build_report(
    corpus: Corpus, policy: PolicyConfig, results: Iterable[ScenarioResult], package_version: str
) -> ReplayReport:
    results = list(results)
    attacks = [r for r in results if r.scenario.label == "attack"]
    detectable = [r for r in attacks if not r.scenario.known_gap]
    stopped = [r for r in detectable if r.ok]
    benign = [r for r in results if r.scenario.label == "benign"]
    checked = [r for r in benign if not r.scenario.known_false_positive]
    flagged = [r for r in checked if not r.ok]

    expecting: dict[str, int] = {}
    detected_by: dict[str, int] = {}
    flagged_benign: dict[str, int] = {}
    documented_fp: dict[str, int] = {}
    for r in detectable:
        for rule in r.scenario.expect_rules:
            expecting[rule] = expecting.get(rule, 0) + 1
            detected_by[rule] = detected_by.get(rule, 0) + int(rule in r.fired)
    for r in checked:
        for rule in r.unexpected:
            flagged_benign[rule] = flagged_benign.get(rule, 0) + 1
    for r in benign:
        if r.scenario.known_false_positive:
            for rule in r.fired:
                documented_fp[rule] = documented_fp.get(rule, 0) + 1
    per_rule = tuple(
        RuleStats(
            rule=rule,
            attacks_expecting=expecting.get(rule, 0),
            attacks_detected=detected_by.get(rule, 0),
            recall=_ratio(detected_by.get(rule, 0), expecting[rule]) if rule in expecting else None,
            benign_scenarios_flagged=flagged_benign.get(rule, 0),
            false_positive_rate=_ratio(flagged_benign.get(rule, 0), len(checked)),
            documented_false_positives=documented_fp.get(rule, 0),
        )
        for rule in sorted(set(expecting) | set(flagged_benign) | set(documented_fp))
    )

    categories: dict[str, list[ScenarioResult]] = {}
    for r in results:
        categories.setdefault(r.scenario.category, []).append(r)
    per_category = tuple(
        CategoryStats(
            category=name,
            attacks=sum(1 for r in rs if r.scenario.label == "attack" and not r.scenario.known_gap),
            stopped=sum(
                1 for r in rs if r.scenario.label == "attack" and not r.scenario.known_gap and r.ok
            ),
            payoff_stopped=sum(
                1
                for r in rs
                if r.scenario.label == "attack" and not r.scenario.known_gap and r.payoff_stopped
            ),
            benign=sum(1 for r in rs if r.scenario.label == "benign"),
        )
        for name, rs in sorted(categories.items())
    )
    benign_steps = [o for r in checked for o in r.outcomes]
    latencies = sorted(x for r in results for x in r.latencies_ms)
    latency = (
        {
            "p50": round(statistics.median(latencies), 4),
            "p99": round(latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))], 4),
            "max": round(latencies[-1], 4),
        }
        if latencies
        else {}
    )
    return ReplayReport(
        corpus_version=corpus.header.corpus_version,
        corpus_sha256=corpus.sha256,
        package_version=package_version,
        preset_version=policy.preset_version,
        policy_sha256=policy.fingerprint(),
        scenarios=len(results),
        attacks=len(attacks),
        attacks_detectable=len(detectable),
        attacks_stopped=len(stopped),
        detection_rate=_ratio(len(stopped), len(detectable)),
        payoff_stop_rate=_ratio(sum(1 for r in detectable if r.payoff_stopped), len(detectable)),
        known_gaps=tuple(
            f"{r.scenario.id}: {r.scenario.known_gap}" for r in attacks if r.scenario.known_gap
        ),
        benign=len(benign),
        benign_checked=len(checked),
        benign_flagged=len(flagged),
        false_positive_rate=_ratio(len(flagged), len(checked)),
        benign_steps=len(benign_steps),
        benign_steps_flagged=sum(
            1 for o in benign_steps if o.expected in (None, "allow") and o.decision != "allow"
        ),
        documented_false_positives=tuple(
            f"{r.scenario.id}: {r.scenario.known_false_positive}"
            for r in benign
            if r.scenario.known_false_positive
        ),
        per_rule=per_rule,
        per_category=per_category,
        failures=tuple(f"{r.scenario.id}: {'; '.join(r.reasons)}" for r in results if not r.ok),
        latency_ms=latency,
    )


def run_corpus(corpus: Corpus, policy: PolicyConfig, package_version: str) -> ReplayReport:
    harness = ReplayHarness(policy)
    package_log = logging.getLogger("redhand_fintech_shield")
    previous = package_log.level
    package_log.setLevel(logging.ERROR)  # scenarios run on fake clocks; startup warnings are noise
    try:
        results = [harness.run(s) for s in corpus.scenarios]
    finally:
        package_log.setLevel(previous)
    return build_report(corpus, harness.policy, results, package_version)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_markdown(report: ReplayReport) -> str:
    """The numbers as a Markdown document (committed as ``docs/detection-results.md``)."""
    lines = [
        "# Detection results",
        "",
        "<!-- Generated by `redhand-shield replay --markdown`; do not edit by hand. -->",
        "",
        f"Corpus `{report.corpus_version}` (sha256 `{report.corpus_sha256[:16]}`), preset "
        f"`{report.preset_version}`, policy fingerprint `{report.policy_sha256[:16]}`, package "
        f"{report.package_version}.",
        "",
        "> **The corpus is synthetic.** Scenarios are written to exercise each rule, in the shape "
        "of "
        "the CRAFTY FALCON kill chain and of ordinary traffic. They are not sampled from real "
        "traffic, so these numbers show whether each control does what it claims on the cases "
        "written down, not how it would perform in production. A 100% detection rate on this "
        "corpus is a regression check, not a security guarantee.",
        "",
        "## Summary",
        "",
        "| Measure | Value |",
        "| :--- | ---: |",
        f"| Scenarios | {report.scenarios} |",
        f"| Attack scenarios the preset should catch | {report.attacks_detectable} |",
        "| Attacks stopped (every expected rule fired) | "
        f"{report.attacks_stopped} ({_pct(report.detection_rate)}) |",
        f"| Money-moving step not allowed | {_pct(report.payoff_stop_rate)} |",
        f"| Documented gaps (attacks not caught, by design) | {len(report.known_gaps)} |",
        f"| Benign scenarios checked | {report.benign_checked} |",
        "| Benign scenarios wrongly flagged | "
        f"{report.benign_flagged} ({_pct(report.false_positive_rate)}) |",
        "| Benign steps wrongly flagged | "
        f"{report.benign_steps_flagged} of {report.benign_steps} |",
        f"| Documented false positives | {len(report.documented_false_positives)} |",
        f"| Scenarios not behaving as the corpus says | {len(report.failures)} |",
        "",
        "## Per rule",
        "",
        "| Rule | Attacks expecting it | Detected | Detection rate | Benign flagged | "
        "False-positive rate | Documented FPs |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for s in report.per_rule:
        lines.append(
            f"| `{s.rule}` | {s.attacks_expecting} | {s.attacks_detected} | "
            f"{'n/a' if s.recall is None else _pct(s.recall)} | {s.benign_scenarios_flagged} | "
            f"{_pct(s.false_positive_rate)} | {s.documented_false_positives} |"
        )
    lines += [
        "",
        "## Per category",
        "",
        "| Category | Attacks | Stopped | Payoff stopped | Benign |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    lines += [
        f"| {c.category} | {c.attacks} | {c.stopped} | {c.payoff_stopped} | {c.benign} |"
        for c in report.per_category
    ]
    lines += [
        "",
        "## Documented gaps",
        "",
        "Attacks the preset does not catch, kept in the corpus so the limit is visible:",
        "",
    ]
    lines += [f"- {g}" for g in report.known_gaps] or ["- none"]
    lines += [
        "",
        "## Documented false positives",
        "",
        "Benign traffic the preset flags by design:",
        "",
    ]
    lines += [f"- {g}" for g in report.documented_false_positives] or ["- none"]
    if report.failures:
        lines += ["", "## Scenarios not behaving as the corpus says", ""]
        lines += [f"- {f}" for f in report.failures]
    lines.append("")
    return "\n".join(lines)
