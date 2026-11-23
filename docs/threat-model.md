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
| **CIAD-2026-0058 Stage 2** | **Split-Transaction Structuring**<br>Attacker splits one large disbursement into several payments that each stay under the HITL threshold. | Sliding-window sum per `(agent_run_id, currency)` over protected tools (default 300 s, at least 2 transactions); trips when the cumulative amount exceeds the per-currency threshold. Never bypassed by the run-wide `hitl_step_up` claim. | `CIAD-2026-0058.R2.structuring` | **Block (Enforce)**: Raises `StructuringError`. Agent quarantined. Fails closed on unknown currency or a full window. |
| **CIAD-2026-0058 Stage 2** | **Reconnaissance-to-Payment Sequence**<br>Attacker enumerates merchants, accounts or beneficiaries and immediately pays out. | Sequence detector: at least 3 calls to configured recon tools inside 30 s followed by a payment tool. | `CIAD-2026-0058.R2.recon_to_payment_sequence` | **Block (Enforce)**: Raises `SequenceViolationError`. Agent quarantined. |
| **CIAD-2026-0058 Stage 3** | **Mule Diversion to a New Beneficiary**<br>Attacker routes funds to a payee not previously vetted. | New-beneficiary gate: a beneficiary outside `known_beneficiaries` above a lower per-currency threshold (USD 1,000, INR 90,000, MYR 4,500, SGD 1,350) on protected tools. | `CIAD-2026-0058.R3.new_beneficiary_high_value` | **HITL or Block**, per `new_beneficiary.action`. Tightened off-hours. |
| **CIAD-2026-0058 Stage 3** | **Approval Replay, Reuse and Substitution**<br>Attacker replays a captured approval, or reuses one for a different amount, payee, tool, run or arguments. | Per-transaction approval: Ed25519 signature from a separate approver key, short TTL, bindings to run/tool/environment/amount/currency/every payee/arguments digest, single-use nonce. | `CIAD-2026-0058.R3.approval_rejected`<br>`CIAD-2026-0058.R3.approval_accepted` | **HITL stays required**: the approval is not honoured and the reason is logged; a mismatching attempt does not burn the nonce. An approval never clears a block. |
| **CIAD-2026-0058 Stage 3** | **Run-Wide Step-Up Abuse**<br>A single step-up flag on a token pre-authorises every payment in a run. | The deprecated `hitl_step_up` claim is reported on every use and can be switched off with `approval.allow_legacy_step_up: false`. | `CIAD-2026-0058.R3.legacy_run_wide_step_up` | **Allow with finding** (while enabled). |
| **CIAD-2026-0058 Stage 2** | **Run Rotation and Payee Fan-Out**<br>Attacker starts a fresh agent run, or pays the same mule from several runs, so each structuring window stays small. | Structuring also aggregates per token subject and per canonical payee across runs; a subject-scope hit quarantines every run of that subject. Window tables are bounded and fail closed when full. | `CIAD-2026-0058.R2.structuring` | **Block (Enforce)**: `StructuringError`; run and `subject:<sub>` quarantined. |
| **CIAD-2026-0058 Stage 2** | **Slow Drain Under Every Window**<br>Attacker moves money slowly enough that no short window trips. | Rolling 24 h cumulative cap per run and per subject; a payment over the cap needs per-transaction step-up (or is blocked). Refused payments are not counted. | `CIAD-2026-0058.R2.cumulative_cap` | **HITL required** (default) or **Block**: `HITLRequiredError` / `CumulativeCapError`. |
| **CIAD-2026-0049 §3** | **Tool Rotation**<br>Attacker spreads calls over many tools to stay under the per-tool velocity limit. | All-tools velocity per agent run (`velocity.max_total_calls`). | `CIAD-2026-0049.R2.velocity_burst` | **Block (Enforce)**: `VelocityExceededError`; run quarantined. |
| **CIAD-2026-0058 Stage 3** | **Payee Spelling and Currency Splitting**<br>Attacker changes case, spacing or Unicode of a payee id, or splits a payout across currencies. | Canonical beneficiary form for comparisons and windows; optional static-rate base-currency aggregation. | `CIAD-2026-0058.R3.new_beneficiary_high_value`<br>`CIAD-2026-0058.R2.structuring` | As the underlying rule. |
| **CIAD-2026-0049 §2** | **Silent Policy Weakening**<br>A local override or copied preset quietly raises thresholds or disables a control. | Overlays may only tighten their base; each loosening must be named in `loosen:`, locked fields can never be loosened, and the loader records the chain, hashes and every loosening in `PolicyConfig.provenance`. Identity, pinning, quarantine and approval rules cannot be overridden. | N/A (Governance Layer) | **Refuse to load**: `PolicyLoadError` naming the field, old and new value. |
| **CIAD-2026-0058 Stage 3** | **Standing Waiver of Human Approval**<br>A permanent exception removes step-up for a payee or tool. | Exemptions are named, approved, time limited (duration cap), must match on tools/subjects/payees/environments, waive only step-up rules and never a block; every use is a finding in the audit log. | `CIAD-2026-0058.R3.exemption_applied` | **Allow with finding**; expired exemptions are ignored and warned about at startup. |
| **CIAD-2026-0049 identity** | **Stolen or Leaked Run Token**<br>A token is exposed in a log or a compromised host and used until it expires. | Revocation by `jti`, subject or run, journaled and picked up live by a running shield; short token TTL; per-run binding. A `jti` replay cache is not used because run tokens are presented on every call. | `CIAD-2026-0058.R1.token_invalid` (`token revoked`) | **Block (Enforce)**: `TokenInvalidError`; the call touches no detector state. |
| **CIAD-2026-0049 identity** | **Signing-Key Compromise and Token Confusion**<br>A signing key leaks, or a token minted for another service is replayed here. | `kid` key ring with `retire_at` for rotation and an overlap window; optional `aud` binding; the approver key must differ from every ring key. | `CIAD-2026-0058.R1.token_invalid` | **Block (Enforce)**: unknown, missing or retired `kid` and a wrong or missing `aud` are refused. |
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

4. **Approvals: Trust in the Approver and the Legacy Flag:**
   - *Limitation:* A per-transaction approval is only as good as what the human saw. The shield builds the `ApprovalRequest`, but the host application must render it faithfully (amount, every payee, the rules that fired) before signing. The approver private key is the host's to protect. Spent nonces live in this process (with an optional local journal), so several workers need a shared `NonceStore`. The arguments digest covers JSON-encodable arguments; objects that are only stringified can make a digest unstable, which makes an approval fail to match rather than match wrongly. The deprecated run-wide `hitl_step_up` claim still pre-authorises a whole run while `approval.allow_legacy_step_up` is true.
   - *Mitigation:* Set `allow_legacy_step_up: false` once approvers issue per-transaction approvals, keep the approver key apart from the token-minting key (the shield enforces different keys), keep `max_ttl_seconds` short, and supply a shared `NonceStore` when running more than one worker.

5. **Audit Trail Tamper-Evidence vs. Tamper-Proofing:**
   - *Limitation:* Hash-chaining is **tamper-evident**, not tamper-proof. An attacker with unrestricted disk write access could rewrite the entire log file with a newly computed hash chain, or truncate the file tail.
   - *Mitigation:* Truncation and total rewrite attacks are detected by capturing the log's tail hash in an external, write-once, or remote WORM/SIEM anchor, and validating using `verify-audit --expected-tail <HASH>`.

6. **Static FX and Holiday Calendars:**
   - *Limitation:* Currency thresholds and public holidays in the preset are static constants. Movable religious and regional bank holidays are not dynamically computed.
   - *Mitigation:* Operators must periodically review currency exchange rates and declare annual regional holiday dates in policy configuration.

7. **RedHand Telemetry Schema Status:**
   - *Notice:* The M4.2 finding schema and M4.3 mode semantics were implemented from design specifications. They are not certified by RedHand and should not be represented as an official RedHand release.

8. **Argument Bindings Are Operator-Declared:**
   - *Limitation:* The rules judge the fields named in `tool_bindings` (or, for unbound tools while `legacy_fallback` is on, the conventional `amount`, `currency` and `beneficiary`). A tool that moves money through an argument the operator did not bind is not judged by the money rules; protected tools must be bound (`require_for_protected`) and fail closed when the bound field is missing or incomplete.
   - *Mitigation:* Bind every tool that can move money, set `legacy_fallback: false` once all of them are bound, and review bindings when a tool's schema changes. Bulk calls are summed and every payee is checked, and a negative element is refused.

9. **Aggregation Limits:**
   - *Limitation:* Beneficiary normalisation is canonicalisation, not a defence against look-alike characters from other scripts. A multi-payee bulk call is summed against the run, subject and cap windows but is not attributed to individual payees. Cross-currency aggregation uses static, operator-supplied rates; a currency without a rate is judged on its own. Window state is per process, so several workers each see only their own share of a subject's traffic, and the 24 h caps reset when the process restarts. Containment of a subject lives in the quarantine registry (journaled locally).
   - *Mitigation:* Review the rates and caps with the thresholds, keep payee ids in a system that issues canonical identifiers, supply shared window and quarantine backends when running more than one worker, and treat a full-tracker or capacity finding as an incident, not noise.

10. **Policy Files Are Trusted Operator Input:**
    - *Limitation:* Anyone who can edit a policy file can list a loosening under `loosen:` (the guardrail forces it to be explicit and recorded, it does not authenticate the editor), and `locked:` protects against mistakes, not against someone who can also edit the base preset. Provenance is recorded in the loaded policy and by `show-policy`; it is not signed and is not yet written into every audit record. A shadowed rule reports `enforced=false` and protects nothing until it is switched back to enforce.
    - *Mitigation:* Keep policy files in review-controlled storage like code, review every `loosen:` and `exemptions:` entry, treat a long-running shadow rule as unfinished work, and anchor the audit log externally. Writing the policy fingerprint into each audit record is on the roadmap (Phase 3.5).

11. **Shared State, Fingerprints and Revocation Reach:**
    - *Limitation:* With the default in-process store each worker has its own windows. A shared `WindowStore` is only as atomic as its implementation, the shield's lock covers one process, so a cumulative cap can overshoot by up to the number of concurrent workers, and workers need a shared time base. The policy fingerprint identifies the rules in force but is neither signed nor secret, and revocation is checked from a journal file that the shield re-reads about once a second, so a revocation takes effect within roughly a second, not instantly, and anyone who can write the journal can revoke (or, by truncating it, un-revoke) a token. Token `aud` is only enforced when configured.
    - *Mitigation:* Treat the window store, journals and audit log as security-relevant storage with restricted write access, run the conformance suite (`testing.window_store_contract`) against any shared backend, anchor the audit tail externally, set `audience` and `token_keys` in production, and keep token TTLs short.
