# Upgrade roadmap

This document is the benchmark for where the project is going. Each phase lists what ships and
how we will know it is done. It describes intent, not a promise of dates. A phase is finished
only when its "Done when" checks pass, and published numbers must come from the repository's own
benchmark harness so anyone can reproduce them.

## Principles

- **Deterministic by design.** Decisions come from rules and cryptography, never from a model.
  Any statistical signal added later is advisory and can never allow a call that a rule blocks.
- **Fail closed.** Unknown currencies, missing amounts, invalid tokens and missing context are
  refused, not guessed at.
- **Honest limits.** Every limitation is documented in the README and the threat model. We say
  "maps to CIAD-2026-0058", never "certified compliant".
- **One node, done properly.** This repository aims to be complete and secure for a single
  deployment. Fleet-scale features (state shared across hosts, managed key custody and approval
  workflows, multi-tenant policy, integrations with specific platforms) are out of scope here and
  are expected to live in separate packages built on tagged releases of this one.
- **No platform code in the core.** The core exposes interfaces. Platform adapters live elsewhere.

## Where we are (Phases 1 to 4 complete)

In-process decorator, Ed25519 per-run tokens, sliding-window detectors, HITL gate, off-hours
tightening, journaled quarantine, hash-chained audit log with rotation and an offline verifier,
extensibility protocols (`protocols.py`), out-of-process MCP Gateway (`MCPGateway` + `redhand-shield gateway`),
multi-cloud and framework adapters (`BedrockConverseAdapter`, `AzureOpenAIAdapter`,
`RedHandSemanticKernelFilter`, `GoogleGenAIAdapter`, `RedHandGuardedTool`, `GenericToolRunner`),
production multi-stage `Dockerfile`, automated latency benchmark suite (`benchmarks/bench_latency.py`),
a CLI, a terminal attack simulation, and 828 tests at 99% coverage. Phase 3 M1 added three
deterministic detectors: split-transaction structuring, new-beneficiary high value, and the
recon-to-payment sequence rule; M2 added per-tool argument bindings so those rules see the field
each tool really pays from; M3 added signed, single-use, per-transaction approvals; M4 closed the detector
bypasses (scopes across runs, caps, tool rotation, payee spelling, currency splitting); M5 added
overlays, shadow rules and exemptions; Phase 3.5 added the integration contract (manifest,
schemas, policy fingerprint, token rotation and revocation, window-store seam, stable API); Phase 4
added the replay corpus and harness, fuzzing, `doctor` and the evidence report. With every
rule exercised on a protected tool (`decision_core_protected`) the in-process p99 measured about
0.35 ms (p50 0.18 ms), and with a layered policy (shadow rule, severity override and an active
exemption, `decision_core_layered`) about 0.6 ms, in the benchmark harness (sandbox run). Measured via `benchmarks/bench_latency.py` before M1:
a full in-process guarded call has a p50 of 0.20 ms and p99 of 0.27 ms, and an out-of-process
MCP Gateway `tools/call` roundtrip has a p50 of 0.37 ms and p99 of 0.54 ms.

Known limits this roadmap exists to address: detector state is per process unless a shared `WindowStore` is supplied; the run-wide `hitl_step_up` flag
is deprecated but still honoured by default; the audit log is tamper-evident but not tamper-proof;
tool pinning covers names, not tool code.

## Phase 1: Foundations (no behaviour changes)

Make the project verifiably trustworthy before adding features.

- Portable tests (POSIX-only checks skipped on Windows) and a configurable latency budget so CI
  on shared runners is not flaky.
- CI on Python 3.11 to 3.14 (Linux), plus latest on macOS and Windows: lint, format check,
  `mypy --strict`, tests with a coverage floor, wheel build, and an install-and-import smoke test
  without optional extras.
- `SECURITY.md` (private vulnerability reporting), `docs/threat-model.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue and PR templates, `CODEOWNERS`, `CHANGELOG.md`.
- Tag-triggered release pipeline: PyPI Trusted Publishing (no stored token), Sigstore
  attestations, SBOM, all third-party Actions pinned to commit SHAs.
- Dependabot, `pip-audit`, OpenSSF Scorecard, pre-commit, read-only default workflow permissions.

**Done when:** CI is green on the full matrix; a tag produces a signed wheel and an SBOM; the
threat model and `SECURITY.md` exist; a fresh `pip install` from PyPI runs the README quickstart.
The coverage floor is set at the level measured at the start of the phase and only ever raised.

## Phase 2: Adoption

Meet agents where they run, and enforce outside the agent's process.

- [x] **MCP gateway:** a proxy (`MCPGateway`) between an MCP client and its tool servers that
  applies the shield to every tool call over JSON-RPC stdio/streams, with no changes to agent code.
- [x] **Adapters:** Zero-vendor-lock-in structural-typing adapters for AWS Bedrock Converse
  (`BedrockConverseAdapter`), Microsoft Azure OpenAI & Semantic Kernel (`AzureOpenAIAdapter`,
  `RedHandSemanticKernelFilter`), Google Cloud Vertex AI / GenAI (`GoogleGenAIAdapter`),
  LangChain / LangGraph (`RedHandGuardedTool`, `guard_langchain_tool`), and a generic tool-use
  loop (`GenericToolRunner`).
- [x] **Docker image** (`Dockerfile` multi-stage build, non-root `redhand` UID `10001`, `/app/data`)
  and `README.md` quickstart rewritten around the gateway, adapters, and published benchmarks.

**Done when:** an unmodified MCP client is protected end to end in the demo; the staging-to-prod
pivot and micro-probe scenarios are blocked at the gateway with the agent holding no reference to
the raw tool; the added latency is measured and its p99 is published next to the in-process figure.
**Status: Complete** — verified with `tests/test_gateway.py`, `tests/test_adapters.py`,
`tests/test_benchmark.py`, and `benchmarks/bench_latency.py` (in-process p99: 0.27 ms;
MCP Gateway loopback p99: 0.54 ms; 253 tests passing at >= 97% coverage).

## Phase 3: Detection depth

New deterministic rules and stronger approval.

- [x] **M1: Structuring, new beneficiary plus high value, and sequence rules.** Structuring is
  several payments just under a threshold that together exceed it; the sequence rule is
  enumeration followed by a payment within a window.
- [x] **M2: Argument binding.** The gateway and the adapters used to read only `amount`,
  `currency` and `beneficiary`, so a tool that names its fields `value`, `payee` or `vpa`, or a
  bulk payout carrying a list of payees, was invisible to every money rule.
  - A `tool_bindings:` policy section maps each tool to the argument paths for amount, currency
    (or a `fixed_currency`) and beneficiary. Paths such as `payments[*].amount` make a bulk call:
    amounts are summed, every payee is checked by the new-beneficiary rule, mixed currencies are
    unknown (fail-closed), and a negative element is refused rather than netted.
  - `require_for_protected` refuses to load a policy with an unbound protected tool; the shipped
    preset sets it. A missing, null or incomplete bound path is unresolved, which the detectors
    already fail closed on protected tools.
  - One shared `context.extract_tool_call_context` replaces the two copies and every adapter and
    the gateway pass `shield.policy.tool_bindings` to it.
- [x] **M3: Per-transaction step-up.** Replaces the run-wide `hitl_step_up` flag as the way to
  satisfy a HITL requirement.
  - The shield attaches an `ApprovalRequest` (id, run, tool, environment, amount, currency,
    every payee, a digest of the exact arguments, the rules that fired) to the exception, the
    gateway response and the evaluation, so the host application can show it to a human.
  - An approval is an Ed25519-signed compact JWS (`ApprovalIssuer`, `redhand-shield approve`)
    that binds all of those fields, expires within `approval.max_ttl_seconds` (default 300) and
    carries a nonce. Verification (`ApprovalVerifier`) checks signature, `typ`, issuer, lifetime
    and every binding; only then is the nonce spent. A rejected attempt does not burn it.
  - Nonces are single use behind the `NonceStore` protocol; `NonceRegistry` is the default, with
    an optional journal so a restart keeps them spent, and it fails closed when full of live
    nonces. Concurrent use of one approval succeeds exactly once.
  - The approver key must differ from the agent-token key (the shield refuses to start
    otherwise), so whoever mints agent tokens cannot approve their own runs.
  - An approval never clears a BLOCK, and a call that needs no step-up ignores it.
  - `hitl_step_up` still works while `approval.allow_legacy_step_up` is true, but each use is
    reported as a `legacy_run_wide_step_up` finding; a rejected approval never falls back to it.
    The flag will be removed before 1.0.
- [x] **M4: Harder aggregation.** Closes the ways the M1 detectors could be sidestepped.
  - **Structuring scopes.** Payments are added up per run and, via `structuring.scopes`, per
    token subject and per payee across runs, so a fresh run id or a second run does not start a
    fresh window. A subject-scope hit quarantines the run and `subject:<sub>`, and the shield
    refuses every later run of that subject. Window tables have a hard `max_keys` limit (the
    payee key space is attacker controlled) and fail closed when full; purging a full table is
    rate limited so it cannot become a CPU sink.
  - **Cumulative caps.** A rolling 24 hour cap per run and per subject (`cumulative_cap`), with
    `hitl_required` (default) or `block`. The cap is checked and recorded in one critical section
    with step-up resolution, so concurrent calls cannot all slip under it, and a refused or
    pending payment is never counted. An approved payment is counted.
  - **All-tools velocity.** `velocity.max_total_calls` counts calls per run across every tool,
    so rotating tools no longer keeps each per-tool count low.
  - **Beneficiary normaliser.** UPI addresses, IBANs (mod-97 checked), IFSC plus account and
    Unicode forms are canonicalised before any comparison, and `known_beneficiaries` is stored in
    the same form. Generic ids keep their case, because merging case-distinct ids could make an
    unknown payee look known.
  - **Cross-currency aggregation.** Optional `aggregation` with static, operator-reviewed rates
    adds payments up in a base currency, so splitting across currencies no longer evades
    structuring or the caps. A currency with no rate fails closed.
- [x] **M5: Composable policies.** User rules layered on the preset without forking it.
  - **`extends:` overlays.** A policy file extends a bundled preset id or another file (depth
    at most 4, cycles refused). The overlay is deep-merged (`key+:` appends to a list), validated,
    then compared with its parent field by field: it may only **tighten**. A field the direction
    table does not know defaults to "must not change", and a test keeps the table complete.
  - **Explicit loosening.** Anything an overlay loosens must be named under `loosen:` (`*`
    wildcard); a stale entry that loosens nothing is an error. A base can `locked:` fields that
    can never be loosened (the preset locks its core floors). `PolicyConfig.provenance` records
    the chain with SHA-256s, every accepted loosening and the locks; `show-policy` prints it.
  - **Per-rule overrides.** `rules:` runs a detector rule in shadow (`observe_only`: reported
    with `enforced=false`, never blocks, quarantines or asks for approval), disables it, or
    re-labels its severity. Identity, pinning, quarantine and approval rules cannot be overridden.
  - **Exemptions.** A named, approved, time-limited waiver of a human step-up requirement, with
    a mandatory match on tools/subjects/payees/environments and a duration cap. It waives only a
    `hitl_required` violation of a step-up rule, never a block, and every use is a finding in the
    audit log. In an overlay, an exemption is a loosening and must be listed.
**Done when:** each rule has positive and negative tests and a documented rationale; a replayed
or reused approval signature is rejected; a payment through a differently named argument or a
bulk list is still judged; the structuring and velocity bypasses above each have a failing test
that now passes; the in-process p99 stays under 2 ms with all rules enabled, re-measured with
`benchmarks/bench_latency.py`.
**Status: Complete** (M1 to M5). Positive and negative tests exist for every rule and every
bypass named above; a replayed or reused approval is rejected (`tests/test_approvals.py`); the
in-process p99 stays under 2 ms with all rules and a layered policy enabled.

## Phase 3.5: Integration contract

The preset will be embedded in the main RedHand app. This phase makes the boundary explicit and
versioned so the two can evolve separately. It adds interfaces only; no platform code enters the
core.

- [x] **Preset manifest.** `PresetManifest` (preset id and version, schema version, advisories,
  fingerprint, rule catalog, extension points), a `redhand.presets` entry point and
  `redhand-shield manifest [--markdown]`. `RULE_CATALOG` describes every rule id and is tied to the
  override/exemption sets by tests; `docs/rules.md` is generated from it.
- [x] **JSON Schema export.** `schemas/` for the policy, finding, audit record, approval request
  and claims, token claims, tool-call context and manifest, with URN ids and a golden test;
  `redhand-shield schema --check`. The diff against RedHand's own M4.2/M4.3 schemas remains open
  until a RedHand release is available.
- [x] **Policy fingerprint.** `policy_sha256` (rules in force, not deployment paths) on every audit
  record and finding, `redhand-shield fingerprint`, `verify-audit --expect-policy`, and
  `schema_version` / `preset_version` with a golden test that pins the preset's content. Logs
  written before fingerprints still verify.
- [x] **Token identity.** An `aud` claim, a `kid` key ring with rotation (`retire_at` ends the
  overlap window; the approver key must differ from every ring key), and revocation by `jti`,
  subject or run (`RevocationStore`, journaled, picked up live by `redhand-shield revoke`).
  **Changed from the first draft:** a `jti` replay cache is not offered, because a run token is
  presented on every call of its run; revocation answers a stolen token instead.
- [x] **`WindowStore` protocol.** All five stateful detectors keep their windows behind it, with
  an in-memory default, a conformance suite (`testing.window_store_contract`) and a second,
  independent implementation that passes the same detector tests. Documented limits: atomicity is
  per process, a shared store needs a shared time base, and a cumulative cap can overshoot by the
  number of concurrent workers.
- [x] **HITL hand-off.** The `ApprovalRequest` is attached to the exception, the gateway response
  and the evaluation (delivered in Phase 3 M3).
- [x] **Stable public API.** `docs/public_api.json` snapshot with a failing test on any change, a
  deprecation policy in `CONTRIBUTING.md`, and a `DeprecationWarning` helper (the `audit_log=` and
  `quarantine_tracker=` aliases now use it).

**Done when:** the manifest and every schema are generated from code and pinned by golden
tests; a token signed with a rotated key verifies during the overlap window and not after; a
revoked token is refused; a decision in the audit log names the policy fingerprint; a fake host
backend passes the same detector tests as the in-memory one.
**Status: Complete.** Verified by `tests/test_manifest.py`, `test_schemas.py`,
`test_fingerprint.py`, `test_token_identity.py`, `test_window_store.py` and `test_public_api.py`;
the in-process p99 stays under 2 ms (protected tool about 0.3 to 0.4 ms, layered policy about
0.5 to 0.6 ms, gateway about 0.8 ms; sandbox run).

## Phase 4: Proof and evidence

Make every claim checkable.

- [x] **Replay corpus** (`corpus/`, `redhand-shield replay`): 108 synthetic scenarios (73 attacks
  the preset should catch, 5 documented gaps, 26 benign, 4 documented false positives) replayed
  through the real shield on fake clocks, with per-rule detection rate and false-positive rate,
  versioned with the corpus (`corpus_version`, `corpus_sha256`, policy fingerprint in every
  result). The corpus policy is an ordinary overlay, so it exercises the M5 machinery. CI runs it
  on one leg, publishes the table to the job summary and uploads the JSON. The harness is
  mutation-tested: weaken a rule and exactly its scenarios fail.
- [x] **Bypass cases in the corpus:** cross-currency splitting, run rotation, payee spelling,
  tool rotation, renamed arguments (bound and unbound), bulk lists (sum, unknown payee, negative
  netting, mixed currency, oversize), each with its expected verdict.
- [x] **Fuzzing and property tests** for the token and approval parsers, the policy loader, the
  audit verifier, the binding resolver, the beneficiary normaliser and the gateway handler. Seeded
  and stdlib-only: **changed from the draft**, which implied a property-testing library; adding one
  would change `uv.lock` for little gain, so the generators are small and deterministic instead.
- [x] **Versioned calendar data:** **changed from the draft**. Rather than separate per-year data
  files, which would need a file loader and fingerprint handling, the preset lists fixed-date
  holidays for 2026 to 2028 explicitly, and the shield warns at startup (and `redhand-shield doctor`
  reports) when the current or next year has no entry. Movable festivals, bank holidays and a wider
  currency table are operator-supplied and stated as such.
- [x] **`report` command:** a self-contained, deterministic, offline HTML report mapping each
  advisory stage to its control and logged evidence, with the chain-verification result, an
  externally anchored tail check and a timeline of blocked and held calls.

**Findings from fuzzing, all fixed:** the policy loader raised raw `RecursionError` and `ValueError`
instead of `PolicyLoadError` and could be made to spend about 40 seconds on a 400-byte alias bomb
(now: size, nesting and expansion limits checked in milliseconds); the audit verifier crashed on
invalid UTF-8 and on hostile continuation headers instead of reporting a broken chain; and the payee
normaliser was not a fixed point, so a control character between a letter and its accent could make
one visible payee appear as two.

**Done when:** the harness runs in CI and publishes per-rule numbers; fuzzing finds no crashes or
verifier bypasses on the supported inputs; the report renders from the demo's audit log offline.
The corpus is synthetic, and its limits are stated beside the numbers.
**Status: Complete** (`tests/test_replay.py`, `test_fuzz.py`, `test_report.py`, `test_diagnostics.py`;
the corpus, replay numbers and report also verified from an installed wheel). "No findings" from
fuzzing is evidence for the inputs tried, not a proof: run it longer with
`REDHAND_FUZZ_ITERATIONS`.

## Phase 5: Launch

- Documentation site with an architecture diagram and the threat model.
- A recorded terminal demo.
- A short comparison of execution-layer enforcement against prompt-based guardrails.
- A `v0.2.0` release with the published benchmark numbers.

**Done when:** a new user can go from `pip install` to a protected agent in two minutes using the
docs alone, and every number in the announcement can be reproduced from the repository.

## Non-goals

Machine-learning detectors in the decision path; certification or compliance claims; presets for
regulators we have not written from the published text; features that require shared
infrastructure across hosts.

## Versioning

Semantic versioning, staying on 0.x until the gateway and per-transaction approval stabilise.
The first public release is `v0.1.0`, cut at the end of Phase 1. Every release has a changelog
entry.
