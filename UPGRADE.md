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

## Where we are (Phase 1 & Phase 2 complete)

In-process decorator, Ed25519 per-run tokens, sliding-window detectors, HITL gate, off-hours
tightening, journaled quarantine, hash-chained audit log with rotation and an offline verifier,
extensibility protocols (`protocols.py`), out-of-process MCP Gateway (`MCPGateway` + `redhand-shield gateway`),
multi-cloud and framework adapters (`BedrockConverseAdapter`, `AzureOpenAIAdapter`,
`RedHandSemanticKernelFilter`, `GoogleGenAIAdapter`, `RedHandGuardedTool`, `GenericToolRunner`),
production multi-stage `Dockerfile`, automated latency benchmark suite (`benchmarks/bench_latency.py`),
a CLI, a terminal attack simulation, and 253 tests. Measured via `benchmarks/bench_latency.py`:
a full in-process guarded call has a p50 of 0.20 ms and p99 of 0.27 ms, and an out-of-process
MCP Gateway `tools/call` roundtrip has a p50 of 0.37 ms and p99 of 0.54 ms.

Known limits this roadmap exists to address: state is per process; step-up approval is a
run-wide flag rather than per transaction; the audit log is tamper-evident but not tamper-proof;
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

- **Structuring:** several payments just under a threshold that together exceed it.
- **New beneficiary plus high value.**
- **Sequence rules:** enumeration followed by a payment within a window.
- **Per-transaction step-up:** a detached Ed25519 signature over amount, beneficiary and a nonce,
  replacing the run-wide flag; nonces are single use.
- **Composable policies:** user rules layered on the preset without forking it.

**Done when:** each rule has positive and negative tests and a documented rationale; a replayed or
reused approval signature is rejected; the in-process p99 stays under 2 ms with all rules enabled.

## Phase 4: Proof and evidence

Make every claim checkable.

- **Replay corpus** of CRAFTY FALCON-style traces plus benign traffic, with a harness that
  reports detection rate and false-positive rate per rule, versioned with the corpus.
- **Property-based tests and fuzzing** for the token parser, policy loader and audit verifier.
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
