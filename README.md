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
- **State is per process.** Sliding windows live in memory, so N workers give each its own
  window. The quarantine journal survives restarts but is not shared live between processes.
- **"Tool pinning" pins tool names per run** via the signed `allowed_tools` claim. It does not
  hash the tool's code or schema.
- **HITL is a boolean claim** minted into the run token (a human pre-authorizes the run). A
  per-transaction detached signature is the stricter design and is not in v0.1.
- **Static thresholds.** Currency ceilings are per-currency constants, not live FX. Review them.
  The preset lists only fixed-date Indian public holidays; add movable and bank holidays yourself.
- **Unauthenticated calls never move detector state or quarantine anyone**, so a forged token
  cannot get a victim's run quarantined. Rate-limit unauthenticated traffic at the edge.
- **Schema alignment.** No RedHand schema was available when this was written; the M4.2 finding
  and M4.3 mode shapes are defined from the design spec (`models.py`). Diff them against your
  RedHand release before wiring telemetry.

## Layout

```
presets/certin_ciad_2026_0058.yaml   declarative policy
src/redhand_fintech_shield/          models, crypto, detectors, audit, interceptor, protocols,
                                     gateway, adapters/, exceptions, CLI
benchmarks/bench_latency.py          reproducible latency benchmark suite (core, gateway, adapters)
Dockerfile                           multi-stage production container (non-root UID 10001)
examples/simulate_crafty_falcon.py   Rich TUI attack simulation
tests/                               253 tests: crypto negatives, detectors, audit tamper cases,
                                     all four stages, both modes, gateway, adapters, benchmarks, CLI
```

## Roadmap

See [UPGRADE.md](UPGRADE.md) for the phased roadmap and the checks that define "done" for each phase.

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Copyright ARCHTIFICIAL Sdn. Bhd.
