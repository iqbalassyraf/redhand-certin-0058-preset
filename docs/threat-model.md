# Threat Model

## System Overview

`redhand-certin-0058-preset` is a deterministic, execution-layer security interceptor for AI-agent tool invocations in financial technology and BFSI environments. It provides defense-in-depth controls mapped specifically against:
* **CERT-In Advisory CIAD-2026-0058**: CRAFTY FALCON targeted intrusion and fraud campaign.
* **CERT-In Advisory CIAD-2026-0049**: AI Agents as Attack Vectors and Autonomous System Exploitation.

The interceptor operates synchronously or asynchronously on the tool execution boundary. **No large language model (LLM) or machine learning (ML) system exists in the decision path.** Decisions are evaluated deterministically from declarative policies, cryptographic token verification, and sliding-window event state.

```
                  +----------------------------------------------+
                  |               AI Agent Process               |
                  |                                              |
Prompt Injection  |  +------------+       +-------------------+  |
Indirect Input -> |  | Agent Core | ----> |  @redhand_guard   |  |
Manipulated State |  +------------+       +---------+---------+  |
                  +---------------------------------|------------+
                                                    | Intercept
                                                    v
                                      +--------------------------+
                                      |   Shield Decision Core   |
                                      | 1. Quarantine Check      |
                                      | 2. Ed25519 Token Verify  |
                                      | 3. Environment Pinning   |
                                      | 4. Off-Hours Adjustment  |
                                      | 5. Micro-Tx / Velocity   |
                                      | 6. HITL Step-Up Gate     |
                                      +-------------+------------+
                                                    |
                         +--------------------------+--------------------------+
                         | (Allow / Observe-Only)                              | (Block - Enforce)
                         v                                                     v
              +---------------------+                               +---------------------+
              | Protected Tool Call |                               | ShieldError Raised  |
              | (Disburse / Settle) |                               | (Agent Quarantined) |
              +----------+----------+                               +----------+----------+
                         |                                                     |
                         +--------------------------+--------------------------+
                                                    |
                                                    v
                                      +--------------------------+
                                      |  SHA-256 Hash-Chained    |
                                      |     Audit Log (JSONL)    |
                                      +--------------------------+
```

---

## Adversary Model & Trust Assumptions

### Adversary Capabilities
1. **Compromised Prompt / Context Injection:** The adversary can deliver malicious indirect prompt injections via customer inputs, document retrieval, or upstream API responses, inducing the agent to invoke tools contrary to intent.
2. **Staging / Dev Credential Compromise:** The adversary possesses valid API keys or JWT tokens minted for staging or development environments and attempts to execute transactions against production tools.
3. **Automated Probing Loops:** The adversary automates iterative micro-transactions (e.g. $0.50 testing charges) to validate stolen payment routes or discover unmonitored channels.
4. **Machine-Speed Enumeration:** The adversary floods APIs with rapid tool calls to harvest account identifiers, brute-force parameters, or overwhelm services.
5. **Off-Hours / Low-Monitoring Exploitation:** The adversary schedules attacks during weekends, holidays, or outside local business hours to delay human detection and response.

### Trust Boundaries & Assumptions
* **Cryptographic Keys:** Signing private keys are assumed to be securely held by an authorized token minting authority. The interceptor possesses the corresponding Ed25519 public key.
* **Interceptor Execution Integrity:** The code wrapping `@redhand_guard` is assumed to be the sole entry point to backend financial functions.
* **Operating System File System:** The local filesystem is assumed to maintain append-only semantics for the audit trail during normal operation, subject to tamper detection via cryptographic chaining.

---

## Attack Vectors & Controls Mapping

| Advisory Reference | Threat Description | Interceptor Control | Rule ID | Enforcement Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **CIAD-2026-0058 Stage 1** | **Staging-to-Production Token Pivot**<br>Attacker uses dev/staging credentials against production payment gateways. | Cryptographic verification of Ed25519 JWS token; validation that token `env` claim strictly matches call `target_env`. | `CIAD-2026-0058.R1.staging_to_prod_pivot`<br>`CIAD-2026-0058.R1.token_invalid` | **Block (Enforce)**: Raises `TokenPivotError` / `TokenInvalidError`. Immediate quarantine of agent run ID. Tool execution prevented. |
| **CIAD-2026-0058 Stage 2** | **Micro-Transaction Probing Loop**<br>Attacker sends micro-value transactions to test ledger integration without tripping alerts. | Sliding-window detector tracking payment count `<= ceiling` (USD 5.00, INR 450, MYR 25, SGD 7) per `agent_run_id` over 60 seconds. | `CIAD-2026-0058.R2.micro_tx_probe` | **Block (Enforce)**: Trips on 2nd probe within window. Raises `MicroTxProbeError`. Agent quarantined with journal persistence. |
| **CIAD-2026-0049 §3** | **Machine-Speed Enumeration Bursts**<br>Attacker executes high-frequency calls to scrape merchant data or verify card ranges. | Sliding-window velocity detector tracking calls per `(agent_run_id, tool_name)` over a 1-second trailing window. | `CIAD-2026-0049.R2.velocity_burst` | **Block (Enforce)**: Trips when calls exceed threshold (default 20/s). Raises `VelocityExceededError`. Agent quarantined. |
| **CIAD-2026-0058 Stage 3** | **Tool Scope Expansion / Unpinned Tools**<br>Attacker directs agent to call settlement or transfer tools beyond its authorized purpose. | Least-privilege tool pinning. Token claims include `allowed_tools` list; verifier rejects unlisted tools. | `CIAD-2026-0058.R3.tool_not_pinned` | **Block (Enforce)**: Raises `ToolNotPinnedError`. Agent quarantined. Tool execution skipped. |
| **CIAD-2026-0058 Stage 3** | **High-Value Disbursement Abuse**<br>Attacker triggers disbursement/settlement transactions exceeding authorized ceilings. | High-value settlement gate. Calls to protected tools exceeding currency threshold (USD 10,000, INR 900,000, etc.) require step-up authorization. | `CIAD-2026-0058.R3.hitl_required` | **Block (Enforce)**: Raises `HITLRequiredError` unless token carries verified `hitl_step_up: true` claim. |
| **CIAD-2026-0058 Stage 4** | **Low-Monitoring Window Attacks**<br>Attacker exploits weekends, holidays, and night hours to bypass passive supervision. | Timezone-aware off-hours evaluator automatically applies `tighten_factor` (0.5), halving probe and velocity limits and making HITL mandatory on protected tools. | `CIAD-2026-0058.R4.off_hours_hitl_required`<br>`CIAD-2026-0058.R4.off_hours_tightened` | **Enforce**: Mandatory HITL enforced on protected tools regardless of transaction amount. Tighter velocity and micro-tx thresholds applied. |
| **CIAD-2026-0049 §4** | **Audit Trail Manipulation & Deletion**<br>Attacker deletes or modifies transaction records to hide illicit activity. | SHA-256 hash-chained JSONL log with previous-record linkage, genesis hashing, continuation headers across rotation, and offline CLI verifier. | N/A (Integrity Layer) | **Tamper Detection**: Any modification, insertion, deletion, or reordering breaks the SHA-256 chain and is identified by `redhand-certin-0058 verify-audit`. |

---

## Honest Security Limits & Mitigations

We explicitly articulate what this library **cannot** defend against. Never treat in-process enforcement as a solitary control:

1. **In-Process Boundary Limitation:**
   - *Limitation:* The shield runs within the same Python process as the agent. If an attacker achieves arbitrary code execution (ACE) or Python frame manipulation (e.g. via an unconstrained code execution tool), they can inspect memory, bypass decorators, or patch object references.
   - *Mitigation:* Deploy tool execution inside an isolated environment (such as an out-of-process MCP gateway or container sandbox) with restricted network egress.

2. **First Micro-Probe Behavior:**
   - *Limitation:* Under CERT-In CIAD-2026-0058, the first micro-transaction is indistinguishable from a legitimate nominal charge. The circuit breaker trips deterministically on the **second** probe within the 60-second window.
   - *Mitigation:* Operators should set conservative probe ceilings and implement upstream anomaly scoring.

3. **Per-Process In-Memory State:**
   - *Limitation:* Sliding-window counters and velocity trackers reside in memory within a single process. Multiple distributed worker processes maintain independent window state unless centralized.
   - *Mitigation:* Quarantine state is persisted to a local disk journal (`quarantine.jsonl`) to survive crashes. Fleet-wide state sharing across distributed clusters is delegated to fleet-scale orchestrators.

4. **Run-Level HITL Flag vs. Per-Transaction Signatures:**
   - *Limitation:* In v0.1, the `hitl_step_up` authorization is a boolean claim bound to the agent run token. It pre-authorizes the run rather than attaching a detached digital signature to specific transaction arguments (amount, beneficiary, single-use nonce).
   - *Mitigation:* The roadmap (Phase 3) introduces per-transaction detached signatures with single-use cryptographic nonces.

5. **Audit Trail Tamper-Evidence vs. Tamper-Proofing:**
   - *Limitation:* Hash-chaining is **tamper-evident**, not tamper-proof. An attacker with unrestricted disk write access could rewrite the entire log file with a newly computed hash chain, or truncate the file tail.
   - *Mitigation:* Truncation and total rewrite attacks are detected by capturing the log's tail hash in an external, write-once, or remote WORM/SIEM anchor, and validating using `verify-audit --expected-tail <HASH>`.

6. **Static FX and Holiday Calendars:**
   - *Limitation:* Currency thresholds and public holidays in the preset are static constants. Movable religious and regional bank holidays are not dynamically computed.
   - *Mitigation:* Operators must periodically review currency exchange rates and declare annual regional holiday dates in policy configuration.

7. **RedHand Telemetry Schema Status:**
   - *Notice:* The M4.2 finding schema and M4.3 mode semantics were implemented from design specifications. They are not certified by RedHand and should not be represented as an official RedHand release.
