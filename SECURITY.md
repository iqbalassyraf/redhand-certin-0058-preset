# Security Policy

## Supported Versions

Security updates are applied to the active release stream:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a vulnerability, please disclose it responsibly.

**Do not open a public GitHub issue or discuss potential vulnerabilities in public forums.**

### Preferred Reporting Channel

Please report all security vulnerabilities privately using **GitHub Private Vulnerability Reporting**:

1. Navigate to the [Security Advisories tab](https://github.com/iqbalassyraf/redhand-certin-0058-preset/security/advisories) of this repository.
2. Click **"Report a vulnerability"** (or use the advisory submission form).
3. Provide a detailed summary, including:
   - Affected component(s) and version(s).
   - Step-by-step reproduction instructions or a minimal proof of concept (PoC).
   - Potential impact and severity assessment.
   - Any proposed remediation or patch.

Submitting via GitHub's private vulnerability advisory system keeps the disclosure confidential and creates a secure collaboration workspace between the finder and project maintainers.

### Response Timelines

* **Initial Acknowledgment:** Within 48 hours of receipt.
* **Triage & Severity Confirmation:** Within 5 business days.
* **Remediation & Patch:** Target patch delivery within 14 business days for high or critical severity issues.
* **Coordinated Disclosure:** A CVE will be requested and a GitHub Security Advisory published alongside the patched release after the fix has been verified.

### Scope and Honest Limits

Please review [`docs/threat-model.md`](docs/threat-model.md) and the documented boundaries in [`README.md`](README.md):
- **In-process boundary:** The core interceptor runs within the agent's Python interpreter process. An adversary who has already achieved arbitrary code execution within the agent process can inspect Python memory, manipulate module globals, or call unadorned functions directly. Defense-in-depth requires network and OS-level egress controls.
- **Micro-transaction baseline:** The first micro-probe is permitted by design under the CERT-In CIAD-2026-0058 specification; the circuit breaker trips on the second probe within the sliding window.
- **Audit log anchoring:** The JSONL audit log is tamper-evident via a cryptographic hash chain. Detecting whole-file replacement or tail truncation requires anchoring the latest tail hash in an external, immutable store.
