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
