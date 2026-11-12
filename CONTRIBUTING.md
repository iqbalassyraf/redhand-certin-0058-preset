# Contributing to redhand-certin-0058-preset

Thank you for your interest in contributing! This project provides deterministic runtime defenses for AI-agent tool calls against CERT-In advisories CIAD-2026-0058 and CIAD-2026-0049.

Please review this guide before submitting code or proposing changes.

---

## Core Principles

1. **Deterministic by Design:** All decisions are made via explicit rules and cryptography. No LLM or non-deterministic ML model may be placed in the decision path.
2. **Fail Closed:** Any missing parameters, unknown currencies, expired tokens, or unhandled states must result in a block/rejection, never a permissive fallback.
3. **Honest Limits:** We state what the project does and does not do. We say "maps to CIAD-2026-0058", never "certified compliant".
4. **Zero Fleet Code in Core:** Fleet-scale infrastructure (distributed consensus, KMS integrations, external UI workflows) belongs in separate packages built on top of this library. The core exposes clean, narrow Python protocols.

---

## Development Setup

The project uses [`uv`](https://github.com/astral-sh/uv) for fast, reproducible dependency management and requires **Python 3.11+**.

```bash
# Clone the repository
git clone https://github.com/iqbalassyraf/redhand-certin-0058-preset.git
cd redhand-certin-0058-preset

# Install dependencies and sync virtual environment
uv sync

# Run the quality gates
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

---

## Branching and Workflow Mandate

* **No direct commits to `main`:** All work must be completed on feature or milestone branches (e.g. `phase-1/m3-governance`).
* **Pull Requests:** Open a pull request against `main`. All CI checks must pass before merging.
* **Never Force-Push:** Do not rewrite pushed branch histories on shared branches.
* **Secrets Hygiene:** Never commit private keys, credentials, tokens, personal identifiers, or environment files (`.env`, `*.pem`, `audit_trail*.jsonl`).

---

## Mandatory Quality Gates

Every pull request must pass all four quality gates:

1. **Linting:**
   ```bash
   uv run ruff check .
   ```
2. **Formatting:**
   ```bash
   uv run ruff format --check .
   ```
   *(Auto-format with `uv run ruff format .`)*
3. **Type Checking:**
   ```bash
   uv run mypy
   ```
   *Strict typing is enabled across all source modules and tests.*
4. **Test Suite & Coverage Floor:**
   ```bash
   uv run pytest
   ```
   *The test suite enforces a strict coverage floor (minimum 97%). New code must include unit and negative tests.*

---

## Pre-Commit Hooks

You can configure pre-commit to run formatting, linting, and type checking before committing:

```bash
uv run pre-commit install
uv run pre-commit run --all-files
```

---

## Reporting Issues

* **Bug Reports:** Open an issue using the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md).
* **Feature Requests:** Open an issue using the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md).
* **Security Disclosures:** Do **not** open a public issue. Follow the instructions in [SECURITY.md](SECURITY.md) to report privately via GitHub Security Advisories.
