# redhand-certin-0058-preset

Deterministic runtime defense for AI-agent tool calls against **CERT-In CIAD-2026-0058
("CRAFTY FALCON")** and **CIAD-2026-0049 ("AI Agents as Attack Vectors")**.

It is two things in one package:

1. a **RedHand preset**: a drop-in interceptor (`@redhand_guard`) that emits RedHand M4.2
   findings and honours M4.3 `observe_only`; and
2. a **standalone toolkit** for fintech/BFSI teams: a policy file, Ed25519 per-run agent
   tokens, sliding-window detectors, a quarantine registry and a hash-chained audit log, with a
   runnable attack simulation. No LLM is in the decision path; no network calls are made.

Measured on this repo's benchmark (5,000 calls, one core): the decision core takes a median of
0.16 ms and p99 of 0.35 ms; a full guarded call (token verification, detectors, the tool, and a
hash-chained disk write) takes a median of 0.20 ms and p99 of 0.46 ms, against a 2 ms budget.
Rare outliers (a single run saw ~2 ms) happen on garbage collection or disk stalls, so the
guarantee is a p99, not a hard ceiling.

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
| 3. Settlement/disbursement abuse | Tool must be in the signed `allowed_tools`; amounts above USD 10,000 on protected tools need a `hitl_step_up` token | `R3.tool_not_pinned`, `R3.hitl_required` |
| 4. Low-monitoring windows | Weekends, holidays, outside 09:00-18:00 IST: probe/velocity limits and HITL thresholds are halved, and HITL is mandatory on protected tools | `R4.off_hours_hitl_required` |
| CIAD-2026-0049 identity | Ed25519 token bound to one `agent_run_id`, 15-minute default TTL, 1-hour policy cap | `R1.token_invalid` |
| CIAD-2026-0049 logs | SHA-256 hash-chained JSONL, offline verifier, rotation that keeps the chain | |

## Use it

```python
from decimal import Decimal
from redhand_fintech_shield import (
    AgentTokenIssuer, AgentTokenVerifier, Env, Shield, ToolCallContext, load_policy, redhand_guard,
)

private, public = AgentTokenIssuer.generate_keypair()       # or: python -m redhand_fintech_shield keygen
shield = Shield(load_policy(), AgentTokenVerifier(public))  # load_policy() = bundled preset

@redhand_guard(shield)
def settle_merchant(merchant_id: str, *, ctx: ToolCallContext) -> str:
    ...  # the real settlement call

token = AgentTokenIssuer(private).mint(
    subject="svc-settlement-agent", agent_run_id="run-42", env=Env.PROD,
    allowed_tools=["settle_merchant"],          # least privilege, pinned by the signature
    ttl_seconds=900, hitl_step_up=False,        # True only after a human co-signs this run
)
settle_merchant("m-1", ctx=ToolCallContext(
    agent_run_id="run-42", tool_name="settle_merchant", target_env=Env.PROD,
    token=token, amount=Decimal("25000"), currency="USD",
))                                              # raises HITLRequiredError; the tool never runs
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

- **In-process gate.** It protects only tools wrapped with `@redhand_guard`, and only as well
  as the agent is prevented from reaching the raw tool functions. CIAD-2026-0049 asks for
  enforcement outside the model; this is an execution-layer control and should sit alongside
  network egress controls, not replace them.
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
src/redhand_fintech_shield/          models, crypto, detectors, audit, interceptor, exceptions, CLI
examples/simulate_crafty_falcon.py   Rich TUI attack simulation
tests/                               121 tests: crypto negatives, detectors, audit tamper cases,
                                     all four stages, both modes, async, threads, latency, CLI
```
