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

## Where we are (Phases 1 and 2 complete, Phase 3 in progress)

In-process decorator, Ed25519 per-run tokens, sliding-window detectors, HITL gate, off-hours
tightening, journaled quarantine, hash-chained audit log with rotation and an offline verifier,
extensibility protocols (`protocols.py`), out-of-process MCP Gateway (`MCPGateway` + `redhand-shield gateway`),
multi-cloud and framework adapters (`BedrockConverseAdapter`, `AzureOpenAIAdapter`,
`RedHandSemanticKernelFilter`, `GoogleGenAIAdapter`, `RedHandGuardedTool`, `GenericToolRunner`),
production multi-stage `Dockerfile`, automated latency benchmark suite (`benchmarks/bench_latency.py`),
a CLI, a terminal attack simulation, and 372 tests at 99% coverage. Phase 3 M1 added three
deterministic detectors: split-transaction structuring, new-beneficiary high value, and the
recon-to-payment sequence rule; M2 added per-tool argument bindings so those rules see the field
each tool really pays from; M3 added signed, single-use, per-transaction approvals. With all rules
on, the in-process p99 measured 0.33 ms in the benchmark harness (sandbox run). Measured via `benchmarks/bench_latency.py` before M1:
a full in-process guarded call has a p50 of 0.20 ms and p99 of 0.27 ms, and an out-of-process
MCP Gateway `tools/call` roundtrip has a p50 of 0.37 ms and p99 of 0.54 ms.

Known limits this roadmap exists to address: state is per process; the run-wide `hitl_step_up` flag
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
- [ ] **M4: Harder aggregation.** Closes the ways the M1 detectors can be sidestepped.
  - Structuring per beneficiary and per subject, across runs, not only per (run, currency).
  - A rolling 24-hour cumulative cap per run and per subject.
  - Velocity across all tools for a run, so rotating tools does not reset the count.
  - A beneficiary normaliser (UPI VPA, IFSC plus account number, IBAN) so one payee cannot
    appear as several.
- [ ] **M5: Composable policies.** User rules layered on the preset without forking it.
  - An `extends:` overlay that can only tighten limits unless a field is explicitly marked
    loosenable.
  - Per-rule `enabled`, `mode` and `severity` overrides, so a new rule can run in shadow while
    the others enforce.
  - Exemptions that carry an expiry and are written to the audit log.

**Done when:** each rule has positive and negative tests and a documented rationale; a replayed
or reused approval signature is rejected; a payment through a differently named argument or a
bulk list is still judged; the structuring and velocity bypasses above each have a failing test
that now passes; the in-process p99 stays under 2 ms with all rules enabled, re-measured with
`benchmarks/bench_latency.py`.

## Phase 3.5: Integration contract

The preset will be embedded in the main RedHand app. This phase makes the boundary explicit and
versioned so the two can evolve separately. It adds interfaces only; no platform code enters the
core.

- **Preset manifest.** `preset_id`, a semantic `preset_version`, a `schema_version` in the YAML,
  advisory references, and a rule catalog (id, stage, severity, rationale, advisory clause).
  Exposed through a `redhand.presets` entry point and a `redhand-shield manifest` command.
- **JSON Schema export** for `PolicyConfig`, `M42Finding`, `AuditRecord` and `ApprovalRequest`,
  with golden-file tests so a schema change is always a visible diff. Diff against the RedHand
  M4.2 and M4.3 schemas as soon as they are available.
- **Policy fingerprint.** The SHA-256 of the canonical policy goes into every audit record and
  finding, so a decision can be traced to the exact policy that made it.
- **Token identity.** An `aud` claim; a keyring keyed by `kid` with rotation and an overlap
  window; a `jti` replay cache; a revocation hook. Each sits behind a protocol in
  `protocols.py` and has an in-memory default.
- **`DetectorStateBackend` protocol.** Sliding-window state moves behind a protocol with the
  current in-memory implementation as the default, so the host can supply a shared store.
  Quarantine already has this seam; the windows do not.
- **HITL hand-off.** The `ApprovalRequest` from Phase 3 M3 is attached to the exception and to
  the finding, so the host can render, approve and sign it without parsing messages.
- **Stable public API.** An explicit list of public names in `__init__.py`, a deprecation
  policy in `CONTRIBUTING.md`, and a CI check that fails on an unannounced removal.

**Done when:** the manifest and every schema are generated from code and pinned by golden
tests; a token signed with a rotated key verifies during the overlap window and not after; a
replayed `jti` is rejected; a decision in the audit log names the policy fingerprint; a
fake host backend passes the same detector tests as the in-memory one.

## Phase 4: Proof and evidence

Make every claim checkable.

- **Replay corpus** of CRAFTY FALCON-style traces plus benign traffic, with a harness that
  reports detection rate and false-positive rate per rule, versioned with the corpus.
- **Property-based tests and fuzzing** for the token parser, policy loader and audit verifier.
- **Bypass cases in the corpus:** cross-currency splitting, tool rotation, differently named
  arguments and bulk-payout lists, each with the expected verdict.
- **Fuzzing of the binding resolver and the beneficiary normaliser**, alongside the token
  parser, policy loader and audit verifier.
- **Versioned calendar data.** Holidays move into a data file per year, with a startup
  warning when the current or next year is missing. Bank holidays and a wider currency table
  are listed as operator-supplied, not shipped as fact.
- **`report` command** that turns an audit log into a self-contained HTML report mapping each
  advisory requirement to the control and the logged evidence, with the chain-verification result
  and a timeline of blocked attacks.

**Done when:** the harness runs in CI and publishes per-rule numbers; fuzzing finds no crashes or
verifier bypasses on the supported inputs; the report renders from the demo's audit log offline.
The corpus is synthetic, and its limits are stated beside the numbers.

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
