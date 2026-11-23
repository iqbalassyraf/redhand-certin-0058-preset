# redhand-certin-0058-preset

Deterministic runtime defense for AI-agent tool calls against **CERT-In CIAD-2026-0058
("CRAFTY FALCON")** and **CIAD-2026-0049 ("AI Agents as Attack Vectors")**.

It is two things in one package:

1. a **RedHand preset**: a drop-in interceptor (`@redhand_guard`) that emits RedHand M4.2
   findings and honours M4.3 `observe_only`; and
2. a **standalone toolkit** for fintech/BFSI teams: a policy file, Ed25519 per-run agent
   tokens, sliding-window detectors, a quarantine registry and a hash-chained audit log, with a
   runnable attack simulation. No LLM is in the decision path; no network calls are made.

Measured on this repo's benchmark (`benchmarks/bench_latency.py`, 1,000 calls, Python 3.12):
the decision core takes a median (p50) of **0.15 ms** and p99 of **0.24 ms**; a full in-process
guarded call (token verification, detectors, tool, and hash-chained disk write) takes a p50 of
**0.20 ms** and p99 of **0.27 ms** (against a 2.0 ms budget); and an out-of-process MCP Gateway
`tools/call` roundtrip over loopback JSON-RPC takes a p50 of **0.37 ms** and p99 of **0.54 ms**
(against a 5.0 ms SLA). Rare outliers happen on garbage collection or disk stalls, so the guarantee
is a p99, not a hard ceiling.

## Install

```bash
pip install redhand-certin-0058-preset            # library + CLI, runtime deps only
pip install "redhand-certin-0058-preset[demo]"    # adds rich, for the terminal simulation
```

Runtime dependencies are pydantic, PyYAML, cryptography, and PyJWT (plus tzdata on Windows).
Nothing else is required, and the decision path makes no network calls.

## Run it in two minutes

```bash
uv sync
uv run python examples/simulate_crafty_falcon.py            # enforce vs observe_only, cinematic
uv run python examples/simulate_crafty_falcon.py --delay 0  # same, instant
uv run pytest && uv run ruff check . && uv run mypy
```

The simulation replays all four kill-chain stages through the real shield with stub tools
(synthetic calls only; nothing leaves the process). Enforce mode stops 8 of 9 malicious steps
and holds attacker funds to **$0.50**; observe-only lets $54,503.50 through but records every
`would_have_blocked` finding. It ends by verifying the audit chain and then showing a one-line
tampering attempt being detected.

## What it blocks

| Kill-chain stage (CIAD-2026-0058) | Control | Rule id |
|---|---|---|
| 1. Staging-to-prod token pivot | Token `env` claim must equal the call's `target_env` | `R1.staging_to_prod_pivot` |
| 2. Micro-transaction probing | 2nd payment `<=` per-currency ceiling (USD 5.00, INR 450, MYR 25, SGD 7) in 60 s trips the breaker and quarantines | `R2.micro_tx_probe` |
| 2. Enumeration bursts (CIAD-2026-0049) | More than 20 calls/s per (agent run, tool) | `R2.velocity_burst` |
| 3. Settlement/disbursement abuse | Tool must be in the signed `allowed_tools`; amounts above USD 10,000 on protected tools need a signed per-transaction approval (or the deprecated `hitl_step_up` token) | `R3.tool_not_pinned`, `R3.hitl_required` |
| 2. Structuring (split payments) | Cumulative amount over 300 s on protected tools above the per-currency threshold, 2+ payments | `R2.structuring` |
| 2. Recon then payout | 3+ recon calls (`list_merchants`, `get_account`, ...) within 30 s followed by a payment tool | `R2.recon_to_payment_sequence` |
| 3. New beneficiary | Payee outside `known_beneficiaries` above USD 1,000 (INR 90,000, MYR 4,500, SGD 1,350) needs step-up or is blocked | `R3.new_beneficiary_high_value` |
| 2. Run rotation, payee fan-out | Structuring also adds up per token subject and per payee across runs; a subject hit contains every run of that subject | `R2.structuring` |
| 2. Slow drain | Rolling 24 h cap per run and per subject; over the cap needs step-up (or is blocked) | `R2.cumulative_cap` |
| 2. Tool rotation | All-tools velocity per run (default preset: 40 calls/s) | `R2.velocity_burst` |
| 4. Low-monitoring windows | Weekends, holidays, outside 09:00-18:00 IST: probe/velocity limits and HITL thresholds are halved, and HITL is mandatory on protected tools | `R4.off_hours_hitl_required` |
| CIAD-2026-0049 identity | Ed25519 token bound to one `agent_run_id`, 15-minute default TTL, 1-hour policy cap | `R1.token_invalid` |
| CIAD-2026-0049 logs | SHA-256 hash-chained JSONL, offline verifier, rotation that keeps the chain | |

## Use it

```python
from decimal import Decimal
from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    Env,
    Shield,
    ToolCallContext,
    load_policy,
    redhand_guard,
)

private, public = AgentTokenIssuer.generate_keypair()  # or: python -m redhand_fintech_shield keygen
shield = Shield(load_policy(), AgentTokenVerifier(public))  # load_policy() = bundled preset


@redhand_guard(shield)
def settle_merchant(
    merchant_id: str, *, ctx: ToolCallContext
) -> str: ...  # the real settlement call


token = AgentTokenIssuer(private).mint(
    subject="svc-settlement-agent",
    agent_run_id="run-42",
    env=Env.PROD,
    allowed_tools=["settle_merchant"],  # least privilege, pinned by the signature
    ttl_seconds=900,
    hitl_step_up=False,  # True only after a human co-signs this run
)
settle_merchant(
    "m-1",
    ctx=ToolCallContext(
        agent_run_id="run-42",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token=token,
        amount=Decimal("25000"),
        currency="USD",
    ),
)  # raises HITLRequiredError; the tool never runs
```

Async tools work the same way. Violations raise typed exceptions (`TokenPivotError`,
`MicroTxProbeError`, `HITLRequiredError`, ...), each carrying its `M42Finding` as `.finding`.
A missing or invalid `ctx` fails closed with `MissingContextError`.

### Modes

Set `mode: enforce | observe_only` in the policy. Every stage is evaluated identically in both
modes, so audit trails are directly comparable. `enforce` raises and skips the tool;
`observe_only` runs the tool, marks findings `would_have_blocked: true, enforced: false`, and
still records quarantine membership (it never blocks on it). The one deliberate difference: in
enforce mode a quarantined run is refused immediately, which also stops an attacker from
flooding the audit log.

### Policy

`presets/certin_ciad_2026_0058.yaml` is validated by Pydantic with unknown keys rejected.
Monetary values are quoted strings (YAML floats are refused). Unknown or missing currencies
fail **closed**: they count as probe candidates and as above the HITL threshold.
`python -m redhand_fintech_shield show-policy` prints the effective policy.

### Tool bindings

The money rules judge the amount, currency and beneficiary a tool is called with. If your tools
name those fields differently, or pay a list of payees, say so in the policy:

```yaml
tool_bindings:
  legacy_fallback: true          # unbound tools keep using amount / currency / beneficiary
  require_for_protected: true    # refuse to load a policy with an unbound protected tool
  tools:
    pay_vendor:
      amount: value
      currency: ccy
      beneficiary: payee.vpa
    upi_send:
      amount: amt
      fixed_currency: INR        # the tool takes no currency argument
      beneficiary: vpa
    bulk_payout:
      amount: payments[*].amount     # summed
      currency: payments[*].currency # must agree, otherwise unknown (fail-closed)
      beneficiary: payments[*].payee # every payee is checked
      max_items: 500
```

A bound tool is judged by its bound fields only. A path that is missing, null or incomplete is
unresolved, which fails closed on protected tools; negative amounts in a bulk call are refused.
The gateway and all adapters read `shield.policy.tool_bindings`; hand-built `ToolCallContext`
objects (the decorator path) are unaffected.

### Composable policies

Do not copy the preset. Extend it:

```yaml
extends: certin_ciad_2026_0058        # a bundled preset id, or a path to another policy file
hitl:
  thresholds: {USD: "7500"}           # tightening needs nothing special
structuring:
  protected_tools+: [pay_vendor]      # `key+:` appends to the base list
loosen:                               # loosening must be named, and is recorded
  - "cumulative_cap.per_subject.USD"
cumulative_cap:
  per_subject: {USD: "250000"}
rules:                                # shadow a rule while tuning it
  CIAD-2026-0058.R2.recon_to_payment_sequence: {mode: observe_only}
```

An overlay may only **tighten** its base. A change that loosens a limit (a higher threshold, a
removed protected tool, a new currency, a rule switched to shadow or off) is refused unless that
exact field is listed under `loosen:`, and a field the base lists under `locked:` can never be
loosened. A `loosen:` entry that loosens nothing is also an error. The loaded policy records its
provenance (chain with SHA-256, accepted loosenings, locks), and `redhand-shield show-policy
overlay.yaml` prints it. See [examples/acme_overlay.yaml](examples/acme_overlay.yaml).

* **Shadow rules.** `rules: {<rule id>: {mode: observe_only}}` keeps a detector running and reports
  what it would have done (`enforced: false`), but it never blocks, quarantines or asks for an
  approval. `enabled: false` switches it off and `severity` re-labels it. Only detector rules can
  be overridden; token, pinning, quarantine and approval rules cannot.
* **Exemptions.** A named, approved, time-limited waiver of a *human step-up requirement*
  (high-value gate, new beneficiary, cumulative cap), matched on tools, subjects, payees or
  environments. It never waives a block, is capped by `exemption_max_days` (90), and every use is
  a finding in the audit log. Adding one in an overlay counts as loosening.

### Aggregation, caps and payee normalisation

```yaml
structuring:
  scopes: [run, subject, beneficiary]   # also add up per token subject and per payee, across runs
velocity:
  max_total_calls: 40                   # per run across ALL tools
aggregation:                            # static, operator-reviewed rates (USD per 1 unit)
  base_currency: USD
  rates: {INR: "0.0111", MYR: "0.2222", SGD: "0.7407"}
cumulative_cap:
  enabled: true
  window_seconds: 86400
  per_run: {USD: "50000", INR: "4500000"}
  per_subject: {USD: "200000", INR: "18000000"}
  action: hitl_required                 # or block (quarantines the run and the subject)
```

A payment over a cap needs a per-transaction approval; a refused or pending payment is not
counted, an approved one is. Payee ids are canonicalised before any comparison (`A@Bank` and
`a@bank` are one UPI address; IBANs ignore spaces and case; other ids keep their case), and
`known_beneficiaries` is stored the same way. Window state is per process, so run one shield per
subject's traffic or supply shared backends; see the threat model.

### Per-transaction approvals

When a call needs step-up, the shield refuses it and hands you exactly what a human must approve.
The approver signs that one transaction; the agent retries with the approval attached.

```bash
redhand-shield keygen keys --name approver     # approver key; keep it apart from the token key
```

```yaml
approval:
  verifier_public_key_path: keys/approver_ed25519_public.pem
  nonce_journal_path: approval_nonces.jsonl
  allow_legacy_step_up: false                  # stop honouring the run-wide hitl_step_up claim
```

```python
try:
    guarded_tool(ctx=ctx)
except HITLRequiredError as exc:
    request = exc.approval_request             # run, tool, amount, currency, payees, arguments digest
    approval = ApprovalIssuer(approver_key).grant(request, approver="alice@bank", ttl_seconds=120)
    # retry the same call with the approval: ToolCallContext(..., approval=approval)
    # (MCP: _meta.approval; CLI: redhand-shield approve request.json --key ... --approver alice)
```

An approval is bound to the run, tool, environment, amount, currency, every payee and the exact
arguments, expires in minutes and works once. A different amount, payee, tool or argument, an
expired or forged approval, or a replay is refused and the call stays at "step-up required". An
approval never clears a block. The old run-wide `hitl_step_up` token claim still works until you
turn `allow_legacy_step_up` off, and every use is reported as a deprecation finding.

## Proof: replay corpus, fuzzing and evidence reports

Claims about the preset are checkable, and the checks run in CI.

* **Replay corpus.** [corpus/](corpus) holds 108 synthetic traces: attacks in the shape of the
  CRAFTY FALCON chain (credential pivot, probing, enumeration, split payments, new payees, off-hours,
  slow drain, token and approval abuse, hostile input) and ordinary traffic.
  `redhand-shield replay` runs them through the real shield and prints, per rule, the detection rate
  on the attacks that should trip it and the false-positive rate on benign traffic
  ([docs/detection-results.md](docs/detection-results.md)). On corpus 1.0.0: 73 of 73 catchable
  attacks stopped, 0 of 26 benign scenarios wrongly flagged. **The corpus is synthetic and written by
  the people who wrote the rules**, so this is a regression check, not a measure of production
  performance. The limits are in the corpus too: five attacks the preset is documented *not* to catch
  (a single micro-payment, an unbound tool, slow payments to a vetted payee, a stolen valid token, a
  payment just under a threshold) and four benign cases it flags by design (two tips inside a minute,
  a dashboard polling too fast, a Saturday settlement). The harness is itself tested: switch a rule
  off, shadow it, loosen a threshold or tighten a ceiling and exactly the right scenarios fail.
* **Fuzzing.** Seeded, stdlib-only fuzzers (`tests/test_fuzz.py`; `REDHAND_FUZZ_ITERATIONS` runs them
  longer) attack the token and approval parsers, the policy loader, the audit verifier, the payee
  normaliser, the binding resolver and the gateway's JSON-RPC handler. The properties: a parser only
  ever fails in its documented way, and nothing that should be refused is accepted (a mutated token, a
  tampered log). They found and fixed real problems, listed in the changelog.
* **Evidence report.** `redhand-shield report audit_trail.jsonl --out report.html` verifies the hash
  chain and writes one self-contained page: the chain result, a table from each advisory stage to the
  control that addresses it and the evidence the log holds, and a timeline of what was blocked. It has
  no scripts and no external requests, renders offline, is deterministic, and escapes everything it
  reads from the log. "No events logged" means nothing triggered; it is not a statement of compliance.
* **Doctor.** `redhand-shield doctor` lists configuration warnings (an exhausted holiday calendar, an
  expiring exemption or key, no audience, a rule in shadow, the deprecated step-up claim). The preset
  ships fixed-date holidays for 2026 to 2028 only; movable festivals, bank holidays and exchange
  rates are operator-supplied.

## Integrating with a host application

Everything a host application needs to consume the preset is machine-readable and versioned.

* **Discover it.** `redhand-shield manifest` (or the `redhand.presets` entry point,
  `redhand_fintech_shield.manifest:get_manifest`) returns the preset id and version, the advisories
  it maps to, its policy fingerprint, and a catalog of every rule: stage, default severity,
  rationale, and whether it can be tuned or waived. [docs/rules.md](docs/rules.md) is generated
  from it and kept in sync by a test.
* **Validate against schemas.** [schemas/](schemas) holds JSON Schemas for the policy, findings,
  audit records, approval requests and claims, token claims, tool-call context and the manifest,
  each with a URN `$id` and a version. A change to any model is a visible diff, and
  `redhand-shield schema --check` fails when they are stale. The finding (M4.2) and mode (M4.3)
  shapes were written from the design specification, not from a RedHand release; diff them against
  RedHand's own schemas before wiring telemetry.
* **Know which policy decided.** Every audit record and finding carries `policy_sha256`, a
  fingerprint of the rules in force (limits, rule overrides, exemptions; not file paths).
  `redhand-shield fingerprint` prints it, and `verify-audit --expect-policy HASH` fails unless
  every record was decided under that policy. The preset's own content is pinned by
  `preset_version` plus a golden fingerprint, so it cannot change silently.
* **Tokens: audience, rotation, revocation.**

  ```yaml
  audience: payments-gateway                 # tokens must carry this aud (AgentTokenIssuer.mint(audience=...))
  token_keys:                                # rotate without an outage
    - {kid: 2026-q4-a, public_key_path: keys/a.pem, retire_at: 2026-12-31T00:00:00Z}
    - {kid: 2026-q4-b, public_key_path: keys/b.pem}
  revocation_journal_path: revoked.jsonl
  ```

  Sign with `AgentTokenIssuer(key, kid="2026-q4-b")`; a token must name a known `kid`, and a key
  stops verifying at its `retire_at`. `redhand-shield keygen keys --kid 2026-q4-b` prints the
  `token_keys` entry. To stop a leaked token, `redhand-shield revoke revoked.jsonl --run RUN
  --reason "..."` (or `--jti`, `--subject`); a running shield picks it up within a second.
  There is deliberately no `jti` replay cache: a run token is presented on every call of its run,
  so rejecting a second use would break normal operation. Revocation is the control for a stolen
  token.
* **Plug in shared state.** `Shield(..., audit=, quarantine=, nonce_store=, revocations=,
  window_store=, telemetry_sink=)` accept your own backends; each is a narrow `typing.Protocol`
  in `redhand_fintech_shield.protocols`. Run
  `redhand_fintech_shield.testing.window_store_contract(factory)` in your tests to check a window
  store. Sharing detector state has limits: the shield's lock makes check-then-record atomic only
  inside one process, so across workers a cumulative cap can overshoot by up to the number of
  concurrent workers, and workers sharing a store need a shared time base (pass a wall-clock
  `monotonic=` to the shield).
* **Depend on a stable API.** [docs/public_api.json](docs/public_api.json) snapshots every name in
  `redhand_fintech_shield.__all__` with its signature; a test fails on any difference. Breaking
  changes and deprecations follow the policy in [CONTRIBUTING.md](CONTRIBUTING.md).

## MCP Gateway & Docker Quickstart

Run the shield out-of-process as a stdio Model Context Protocol (MCP) gateway so the agent never
holds a direct reference to raw tool implementations:

```bash
# Generate an Ed25519 keypair for token signing and verification
redhand-shield keygen --out-dir keys

# Start the out-of-process MCP gateway over stdio
redhand-shield gateway \
  --public-key keys/redhand_ed25519_public.pem \
  --target-env prod \
  --mode enforce
```

### Docker Container Quickstart

Build and run the hardened multi-stage container (runs as unprivileged user `redhand` UID `10001`
with `/app/data` for audit and quarantine journals):

```bash
docker build -t redhand-shield .

docker run --rm -i \
  -v "$(pwd)/keys:/app/keys:ro" \
  -v "$(pwd)/data:/app/data" \
  redhand-shield gateway \
  --public-key /app/keys/redhand_ed25519_public.pem \
  --audit-path /app/data/audit_trail.jsonl \
  --quarantine-journal /app/data/quarantine.jsonl \
  --target-env prod \
  --mode enforce
```

Example generic MCP client configuration (`mcp_config.json`):

```json
{
  "mcpServers": {
    "redhand-fintech-shield": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/abs/path/to/keys:/app/keys:ro",
        "-v", "/abs/path/to/data:/app/data",
        "redhand-shield",
        "gateway",
        "--public-key", "/app/keys/redhand_ed25519_public.pem",
        "--audit-path", "/app/data/audit_trail.jsonl",
        "--quarantine-journal", "/app/data/quarantine.jsonl"
      ]
    }
  }
}
```

## Multi-Cloud & Framework Adapters

All adapters use structural typing with zero heavy SDK lock-in in the core package. Assuming
`shield` and `token` are initialized as shown above:

### AWS Bedrock Converse

```python
from redhand_fintech_shield.adapters import BedrockConverseAdapter

adapter = BedrockConverseAdapter(shield, {"charge_card": charge_card})
tool_result = adapter.handle_tool_use_block(
    {
        "toolUse": {
            "toolUseId": "tooluse_01",
            "name": "charge_card",
            "input": {"amount": "100.00", "currency": "USD", "token": token, "target_env": "prod"},
        }
    }
)
```

### Microsoft Azure OpenAI

```python
from redhand_fintech_shield.adapters import AzureOpenAIAdapter

adapter = AzureOpenAIAdapter(shield, {"charge_card": charge_card})
tool_msg = adapter.handle_tool_call(
    {
        "id": "call_01",
        "type": "function",
        "function": {
            "name": "charge_card",
            "arguments": {
                "amount": "100.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
            },
        },
    }
)
```

### Google Cloud Vertex AI / GenAI

```python
from redhand_fintech_shield.adapters import GoogleGenAIAdapter

adapter = GoogleGenAIAdapter(shield, {"charge_card": charge_card})
fn_resp = adapter.handle_function_call(
    {
        "function_call": {
            "name": "charge_card",
            "args": {"amount": "100.00", "currency": "USD", "token": token, "target_env": "prod"},
            "id": "call_01",
        }
    }
)
```

### LangChain / LangGraph

```python
from redhand_fintech_shield.adapters import RedHandGuardedTool

guarded_tool = RedHandGuardedTool(my_langchain_tool, shield)
result = guarded_tool.run(amount="100.00", currency="USD", token=token, target_env="prod")
# Async: result = await guarded_tool.arun(amount="100.00", currency="USD", token=token, target_env="prod")
```

### Generic Agent Loop

```python
from redhand_fintech_shield.adapters import GenericToolRunner

runner = GenericToolRunner(shield, {"charge_card": charge_card})
result = runner.run(
    "charge_card",
    {"amount": "100.00", "currency": "USD", "token": token, "target_env": "prod"},
)
```

## Performance & Benchmarks

Reproduce on your host with:

```bash
uv run python benchmarks/bench_latency.py --iterations 1000
```

Measured on Linux (Python 3.12.16, `iterations=1000`, `warmup=100`, `Mode.ENFORCE` with JSONL
audit logging):

| Component / Path | p50 (ms) | p95 (ms) | p99 (ms) | Budget / SLA |
|---|---:|---:|---:|---|
| Decision Core (`Shield.evaluate`) | 0.1543 | 0.1778 | 0.2389 | < 2.0 ms |
| In-Process Guarded Call (`@redhand_guard`) | 0.1986 | 0.2251 | 0.2699 | < 2.0 ms |
| Out-of-Process MCP Gateway (loopback JSON-RPC) | 0.3690 | 0.4342 | 0.5400 | < 5.0 ms |
| AWS Bedrock Converse (`BedrockConverseAdapter`) | 0.2139 | 0.2476 | 0.2792 | < 2.0 ms |
| Azure OpenAI (`AzureOpenAIAdapter`) | 0.2172 | 0.2481 | 0.2770 | < 2.0 ms |
| Google GenAI (`GoogleGenAIAdapter`) | 0.2150 | 0.2483 | 0.2828 | < 2.0 ms |
| LangChain Sync (`RedHandGuardedTool.run`) | 0.2125 | 0.2460 | 0.3005 | < 2.0 ms |
| LangChain Async (`RedHandGuardedTool.arun`) | 0.2151 | 0.2496 | 0.3002 | < 2.0 ms |

Net MCP Gateway proxy overhead over a raw async no-op tool (`0.0002 ms` p50): **0.37 ms** (p50),
**0.43 ms** (p95), and **0.54 ms** (p99).

## Specification

**Token** (compact JWS, `alg=EdDSA`, algorithm pinned on verify so `none`/HMAC confusion fails):
`iss`, `sub`, `agent_run_id`, `env`, `allowed_tools`, `hitl_step_up`, `iat`, `exp`, `jti`.
The verifier also requires `agent_run_id` to match the call and `exp - iat` to be within the
policy maximum.

**Audit log** (`audit_trail.jsonl`, one record per line, every verdict including blocks):

```
canonical(x)  = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
record_hash_n = SHA256( canonical(record_n without "record_hash") )   # includes prev_hash
prev_hash_n   = record_hash_{n-1};   prev_hash_0 = "0" * 64
```

Raw tokens are never logged, only `sha256:<digest>`. After `rotate()` the new file begins with a
`chain_continuation` header carrying the previous tail hash, so
`python -m redhand_fintech_shield verify-audit old.jsonl audit_trail.jsonl` verifies across files.

## Limits you should know before deploying

- **In-process gate vs. out-of-process gateway.** `@redhand_guard` and in-process adapters
  protect only wrapped tools, and only as well as the agent is prevented from reaching raw tool
  functions. For out-of-process isolation where the agent holds no direct reference to raw tools,
  run `MCPGateway` (`redhand-shield gateway`) inside the provided Docker container alongside
  network egress controls.
- **The first probe passes.** A single `$0.50` payment is indistinguishable from a legitimate
  one; the breaker trips on the second, as the advisory specifies.
- **Tamper-evident, not tamper-proof.** Someone who can rewrite the whole file can forge a
  consistent chain, and truncation is invisible without an external anchor. Store `tail_hash`
  somewhere write-once and pass it back with `--expected-tail`. One process must own a log file.
  Retention (180+ days) is an operations concern; rotation preserves the chain.
- **State is per process by default.** Sliding windows live in memory, so N workers give each its
  own window. Supply a shared `WindowStore` (and quarantine, nonce and revocation stores) to share
  them; see "Integrating with a host application" for what a shared store can and cannot
  guarantee. The quarantine, nonce and revocation journals survive restarts.
- **"Tool pinning" pins tool names per run** via the signed `allowed_tools` claim. It does not
  hash the tool's code or schema.
- **Step-up is per transaction.** A signed, single-use approval bound to the exact transaction
  authorises it. The older run-wide `hitl_step_up` claim still works while
  `approval.allow_legacy_step_up` is true (every use is reported, and it is slated for removal);
  turn it off once your approvers issue approvals.
- **Static thresholds.** Currency ceilings are per-currency constants, not live FX. Review them.
  The preset lists only fixed-date Indian public holidays; add movable and bank holidays yourself.
- **Unauthenticated calls never move detector state or quarantine anyone**, so a forged token
  cannot get a victim's run quarantined. Rate-limit unauthenticated traffic at the edge.
- **Schema alignment.** No RedHand schema was available when this was written; the M4.2 finding
  and M4.3 mode shapes are defined from the design spec (`models.py`) and exported to `schemas/`.
  Diff them against your RedHand release before wiring telemetry.

## Layout

```
presets/certin_ciad_2026_0058.yaml   declarative policy (versioned, with locked floors)
schemas/                             JSON Schemas for every document exchanged with a host
docs/                                threat model, rule catalog (generated), public API snapshot
src/redhand_fintech_shield/          models, crypto, detectors, window store, audit, interceptor,
                                     approvals, revocations, layers (overlays), manifest, schemas,
                                     protocols, gateway, adapters/, exceptions, CLI
benchmarks/bench_latency.py          reproducible latency benchmark suite (core, gateway, adapters)
Dockerfile                           multi-stage production container (non-root UID 10001)
examples/                            attack simulation and an example policy overlay
corpus/                              synthetic attack and benign traces, policy and generator
tests/                               unit, negative, concurrency, contract and fuzz tests; every
                                     detector test also runs against an independent window store
```

## Roadmap

See [UPGRADE.md](UPGRADE.md) for the phased roadmap and the checks that define "done" for each phase.

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Copyright ARCHTIFICIAL Sdn. Bhd.
