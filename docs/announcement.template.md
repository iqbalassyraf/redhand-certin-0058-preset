# redhand-certin-0058-preset {{package_version}}

A deterministic runtime interceptor that stops AI agents from moving money the way CERT-In
CIAD-2026-0058 (CRAFTY FALCON) and CIAD-2026-0049 describe. It sits on the tool-execution
boundary, so a manipulated agent cannot reach a payment tool except through it. No model is in
the decision path.

Every number below is produced by a command in this repository. The last section lists them.

## What it does

- Pins each agent run to one environment and one tool list with an Ed25519 token, so a staging
  credential replayed against production, or a tool the run was never granted, is refused.
- Detects micro-transaction probing, enumeration bursts, recon-then-payout sequences, split
  payments across runs, payees and currencies, and slow drains against a rolling cap.
- Requires a signed, single-use approval for a high-value or new-beneficiary payment.
- Writes every decision to a SHA-256 hash chain that verifies offline.
- Ships {{rules}} documented rules, each with its severity and whether it can be tuned or waived.

## Results on the replay corpus

The corpus is synthetic: {{scenarios}} scenarios written to exercise each rule, of which {{attacks}}
are attacks the preset should catch and {{benign}} are ordinary traffic.

- The preset stops {{attacks_stopped}} of {{attacks}} attacks ({{detection_pct}}%): every expected
  rule fired.
- It wrongly flags {{benign_flagged}} of {{benign}} benign scenarios.
- {{gaps}} attacks are documented gaps the preset does not catch, by design, and
  {{false_positives}} benign cases are documented false positives. Both are listed in the
  detection results rather than hidden.

A full score on a corpus we wrote ourselves is a regression check. It shows each control does what
it claims on the cases written down. It does not measure performance on real traffic.

## Measured on one machine

Latency of one decision, with no model and no network, measured over {{bench_iterations}}
iterations on {{platform}} with Python {{python}}:

| Path | p50 | p95 | p99 |
|---|---|---|---|
| Decision core | {{core_p50_ms}} ms | {{core_p95_ms}} ms | {{core_p99_ms}} ms |
| In-process guarded call | {{guarded_p50_ms}} ms | {{guarded_p95_ms}} ms | {{guarded_p99_ms}} ms |
| Out-of-process gateway, loopback | {{gateway_p50_ms}} ms | {{gateway_p95_ms}} ms | {{gateway_p99_ms}} ms |

The test suite had {{tests_passed}} passing tests at {{coverage_pct}}% line coverage when these
were recorded. These figures depend on the machine and will differ on yours; run the commands
below. They are measurements, not guarantees: a rare garbage-collection or disk stall will exceed
the p99.

## What it does not do

- It runs in the agent's process. An attacker with code execution can bypass it and a stolen
  signing key mints valid tokens. Run tools behind the out-of-process gateway or a sandbox.
- It judges the argument fields you bind to each tool; a money-moving argument nobody bound is not
  judged.
- The first micro-probe looks like a small legitimate payment. The breaker trips on the second.
- The M4.2 finding schema and M4.3 mode semantics were implemented from design specifications and
  are not certified by RedHand.

The full list is in the threat model.

## Identity of this release

- Package version `{{package_version}}`, preset version `{{preset_version}}`.
- Preset policy fingerprint `{{preset_fingerprint}}`; the corpus runs under an overlay with
  fingerprint `{{corpus_policy_fingerprint}}`.
- Replay corpus `{{corpus_version}}`, sha256 `{{corpus_sha}}`.
- {{public_api_names}} public names, snapshotted so a change is a visible diff.

## Reproduce every number

| Number | Command |
|---|---|
| Scenarios, attacks, stopped, benign, flagged, gaps, false positives | `redhand-shield replay` |
| Rule count, preset version, preset fingerprint | `redhand-shield manifest` |
| Public API size | `redhand-shield api` |
| All exact numbers at once | `python scripts/release_numbers.py` |
| Latency percentiles | `python benchmarks/bench_latency.py --iterations 1000` |
| Tests passed and coverage | `pytest -q` |
| Re-measure and re-record the machine-dependent numbers | `python scripts/release_numbers.py --measure` |
| Check this page against the repository | `python scripts/release_numbers.py --render --check` |

Install with `pip install redhand-certin-0058-preset`, then follow the quickstart.
