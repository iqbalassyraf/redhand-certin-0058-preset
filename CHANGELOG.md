# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions continuous integration matrix covering Linux (Python 3.11-3.14), macOS, and Windows.
- Wheel packaging and clean virtualenv smoke test job in CI.
- Configurable latency test budget via `REDHAND_LATENCY_BUDGET_MS` environment variable.
- Enforced test coverage floor at 97% with `pytest-cov`.
- Cross-platform test suite portability ensuring Windows compatibility for file permissions tests.
- Comprehensive `docs/threat-model.md` mapping controls to CERT-In CIAD-2026-0058 and CIAD-2026-0049.
- Formal security policy (`SECURITY.md`) using GitHub Private Vulnerability Reporting.
- Community and repository governance standards: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`.
- Issue and pull request templates (`.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`).
- Pre-commit configuration (`.pre-commit-config.yaml`) with pinned hooks for `ruff`, `ruff-format`, and `mypy`.
- Authoritative project roadmap documented in `UPGRADE.md`.
- Extensibility protocols (`PolicyEvaluator`, `TokenVerifier`, `AuditLogger`, `QuarantineStore`, `TelemetrySink`, `ToolExecutor`, `Clock`, `MonotonicClock`) in `src/redhand_fintech_shield/protocols.py` (Phase 2 M1).
- Out-of-process Model Context Protocol (MCP) Gateway (`MCPGateway`) with `stdio`/stream JSON-RPC transport and `redhand-shield gateway` CLI subcommand (Phase 2 M2).
- `redhand-shield` CLI script entrypoint alias alongside `redhand-certin-0058`.
- Zero-vendor-lock-in platform and framework adapters in `src/redhand_fintech_shield/adapters/`: `BedrockConverseAdapter`, `AzureOpenAIAdapter`, `RedHandSemanticKernelFilter`, `GoogleGenAIAdapter`, `RedHandGuardedTool`, `guard_langchain_tool`, and `GenericToolRunner` (Phase 2 M3).
- Production multi-stage `Dockerfile` (`python:3.12-slim-bookworm`, unprivileged `redhand` UID `10001`, `/app/data`) and `.dockerignore` (Phase 2 M4).
- Automated latency benchmark suite (`benchmarks/bench_latency.py`) covering Decision Core, In-Process Guarded Call, MCP Gateway loopback, and Multi-Cloud Adapters, plus cross-platform smoke test (`tests/test_benchmark.py`) (Phase 2 M4).
- Updated `README.md` with MCP Gateway & Docker quickstart, multi-cloud adapter snippets, and empirical latency benchmark table; marked Phase 2 complete in `UPGRADE.md` (Phase 2 M4).
- Phase 3 M1 detectors: split-transaction structuring (`CIAD-2026-0058.R2.structuring`), recon-to-payment sequence (`CIAD-2026-0058.R2.recon_to_payment_sequence`) and new-beneficiary high value (`CIAD-2026-0058.R3.new_beneficiary_high_value`), with `structuring`, `new_beneficiary` and `sequence` sections in the preset and new exceptions `StructuringError`, `NewBeneficiaryError` and `SequenceViolationError`.
- Roadmap: Phase 3 milestones M2 to M5 (argument binding, per-transaction step-up, harder aggregation, composable policies) and a new Phase 3.5 integration contract in `UPGRADE.md`.
- Phase 3 M2 argument bindings: `tool_bindings` policy section (`ToolBinding`, `ToolBindingsPolicy`) mapping each tool to the argument paths for amount, currency and beneficiary, with list aggregation (`payments[*].amount`), `fixed_currency`, `legacy_fallback` and `require_for_protected`. New `bindings.py` resolver and a single shared `context.extract_tool_call_context` used by the gateway and all adapters. `ToolCallContext.beneficiaries` lets the new-beneficiary rule judge every payee of a bulk call. The shipped preset binds its protected tools.
- Phase 3 M3 per-transaction step-up: `ApprovalRequest` attached to HITL exceptions, gateway responses and evaluations; `ApprovalIssuer` / `ApprovalVerifier` for signed approvals bound to run, tool, environment, amount, currency, every payee and an arguments digest; single-use nonces behind the new `NonceStore` protocol (`NonceRegistry`, optional journal); `approval` policy section; `redhand-shield approve` and `keygen --name`; rule ids `R3.approval_accepted`, `R3.approval_rejected` and `R3.legacy_run_wide_step_up`. `ToolCallContext` gains `approval` and `arguments_digest`; the audit log stores only a hash of the approval.
- Phase 3 M4 harder aggregation: `structuring.scopes` (run, subject, payee across runs) with a `max_keys` fail-closed limit; subject containment (`subject:<sub>` quarantine); `cumulative_cap` (rolling per-run and per-subject caps, `hitl_required` or `block`) and `CumulativeCapError`; `velocity.max_total_calls` (all-tools velocity); `normalize.canonical_beneficiary` (UPI, IBAN, IFSC plus account, Unicode) applied to extraction and to `known_beneficiaries`; optional `aggregation` (static base-currency rates) for cross-currency structuring and caps. Rule id `CIAD-2026-0058.R2.cumulative_cap`.
- `decision_core_protected` benchmark that exercises every gate and window on a protected tool.
- Phase 3 M5 composable policies: `extends:` overlays (bundled preset id or file; deep merge; `key+:` appends) that may only tighten their base, with explicit `loosen:` entries, base-declared `locked:` floors and `PolicyConfig.provenance` (chain with SHA-256, accepted loosenings, locks); `rules:` overrides (shadow `observe_only`, disable, severity) for detector rules only; time-limited audited `exemptions:` that waive human step-up requirements only (`R3.exemption_applied`). New `layers.py`, `rules.py`, `examples/acme_overlay.yaml`, and a `decision_core_layered` benchmark.

### Changed
- Policies loaded from a file always carry `provenance`; a `provenance:` key written in a file is ignored. `Evaluation.primary_finding()` prefers enforced findings, so a shadow finding never raises.
- The shipped preset gains a `locked:` list (`quarantine_on_block`, `tool_bindings.require_for_protected`, `hitl.protected_tools`, `off_hours.enabled`).
- The shipped preset turns the new protections on (scopes, cumulative caps, all-tools velocity, USD-based aggregation). A subject-scope structuring hit now contains every run of that token subject.
- Beneficiary identifiers are canonicalised, so audit records and approvals carry the canonical payee (for example `a@bank` for `A@Bank`).
- The run-wide `hitl_step_up` token claim is deprecated: it is still honoured while `approval.allow_legacy_step_up` is true (the default), each use is reported as a finding, and it will be removed before 1.0.
- The shield refuses to start if the approval verifier key equals the agent-token verifier key.
- Bulk calls reject negative elements and unresolved bound fields are audited with a `binding_note` and treated as fail-closed on protected tools.

## [0.1.0] - 2026-11-12

### Added
- Deterministic runtime interceptor core (`Shield`, `@redhand_guard`) for sync and async tool calls.
- CERT-In CIAD-2026-0058 preset policy in `presets/certin_ciad_2026_0058.yaml`.
- Ephemeral agent run identity tokens: compact JWS signed with Ed25519 (`alg=EdDSA`), algorithm-pinned verifier.
- Stage 1 defense: token-to-environment binding and staging-to-prod pivot detector (`TokenPivotError`).
- Stage 2 defense: sliding-window micro-transaction probing detector tripping on the 2nd probe within 60s (`MicroTxProbeError`).
- Stage 2 defense: per-second tool velocity burst detector (`VelocityExceededError`).
- Stage 3 defense: cryptographic tool pinning via token claims (`ToolNotPinnedError`).
- Stage 3 defense: high-value settlement and disbursement human-in-the-loop step-up gate (`HITLRequiredError`).
- Stage 4 defense: timezone-aware off-hours tightening for weekends, holidays, and non-business hours.
- In-memory quarantine registry with durable local JSONL journal replay (`QuarantineRegistry`).
- SHA-256 hash-chained JSONL audit log with rotation, continuation headers, and offline verifier (`HashChainedAuditLog`).
- CLI commands: `keygen` (Ed25519 keypair generation), `verify-audit` (audit chain verification), `show-policy` (policy validator).
- Rich terminal attack simulation script demonstrating enforce vs observe-only modes in `examples/simulate_crafty_falcon.py`.
- 121 comprehensive unit, negative, concurrency, and latency tests.
