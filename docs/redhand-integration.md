# RedHand integration map (draft, Phase 6.0)

Status: **draft from reading `iqbalassyraf/redhand` at commit `da8ecb5` (read-only).** Nothing in
RedHand was changed. This page records what the host actually is, where this preset meets it, and
what is missing. It replaces assumptions this package made before the host code was available.

## What RedHand is (from its code)

- A Python 3.11, FastAPI, `uv`-workspace monorepo: `agentwall/` (the MCP gateway, :8080),
  `services/redhand-core/` (the control plane, :8000, Postgres via Supabase), `packages/redhand-sdk/`,
  `apps/redhand-ui/` (Next.js). Same language, validation library (Pydantic v2, `extra="forbid"`),
  linter (Ruff) and test runner (pytest) as this package.
- Agents get a **passport** (id, tenant, scopes, status `active|frozen|revoked|expired`, version) and
  exchange an agent key for a **10-minute Ed25519 (EdDSA) JWT**; the gateway holds public keys only
  (`agentwall/src/gateway/identity.py`, issuer `redhand-core`, audience `redhand-gateway`, JWKS).
- `McpGateway._handle` (`agentwall/src/gateway/service.py`) is a fixed pipeline: authenticate,
  message shape, passport and server context, tool authorization (honeytokens, scopes, pins, budget,
  loops, destinations, argument guardrails), forward, redact. Every decision is recorded to the
  **Black Box**, a per-organisation, append-only, SHA-256 hash-chained log in core (ADR 0030). Raw
  arguments are never stored: names and a digest only.
- Each control has an operator kill switch and fails closed. The gateway adds at most 10 ms p50 / 50 ms
  p99 (RedHand's budget); this package's decision core measured well under that.
- RedHand's working rules (`CLAUDE.md`) require a written plan and approval for anything touching auth,
  tokens, the gateway, schemas or dependencies; no commit, push or merge to its `main` without being
  asked. Any RedHand change below follows that process.

## Corrections to what this package assumed

1. **"M4.2 finding" and "M4.3 mode" are RedHand Radar milestones, not a general finding contract.**
   RedHand's `FindingItem` (`services/redhand-core/src/redhand_core/radar/models.py`) has a fixed rule
   id (`RAD-(INJ|OUT|LOOP|DST|MDL)-nnn`), `kind`, `family`, `severity` (low, medium, high),
   `confidence`, `place`, `evasion`, `would_block`, and **never carries free text**. Modes are
   `off | observe | block` (and `off | observe | throttle` for loops). This package's `M42Finding`
   (`rule_id` like `CIAD-2026-0058.R2.structuring`, severity up to `critical`, a free-text `detail`,
   `stage`, `decision`) does not match, and `Mode.OBSERVE_ONLY = "observe_only"` is spelled
   differently. The README and threat-model line "implemented from design specifications, not
   certified" stays true, and is now specific: the shapes differ, so a mapper is required (6.1).
2. **RedHand has no money concept.** Budget Guard counts forwarded tool calls per agent per day
   ("RedHand sees calls through the gateway, not LLM tokens or money"). Amounts, currencies and
   payees exist in this package's argument bindings, not in RedHand.
3. **RedHand has no run token or environment claim.** Its token identifies an agent passport and a
   passport version, not a single `agent_run_id` or a `prod`/`staging` environment.

## Seam by seam

| Seam | RedHand today | This preset | Gap and proposed handling |
|---|---|---|---|
| Where to hook | `_handle` stage 4, after scopes and before forward | `Shield.evaluate(ctx)` | New stage in the gateway: build a `ToolCallContext` from the JSON-RPC `tools/call` and the passport. Needs an ADR and plan (gateway change). |
| Identity | EdDSA JWT, per agent, 10 min, `passport_version` | EdDSA JWT, per run, `agent_run_id`, `env`, `allowed_tools`, `aud`, `kid`, revocation | Do not mint a second token. Derive the run context from RedHand's verified identity, and have the gateway (which already verified the token) pass trusted claims to the shield through a `TokenVerifier` adapter; the shield's own token check is then bypassed by design, with the trust boundary documented. Open question: what is a "run" (session id?) and where does `env` come from (server config?). |
| Tool pinning | Scopes and strict pins by name | `allowed_tools` | Same idea; use RedHand scopes as the source of truth, do not duplicate. |
| Money rules (structuring, caps, new beneficiary, HITL threshold) | Absent | Core of the preset | Needs `tool_bindings` per customer tool. Applies only to tenants that opt in and bind payment tools. |
| Behavioural limits | Budget Guard (call count), loop meter | micro-probe, velocity, sequence | Overlap on velocity; keep both, report which fired. Shared state: RedHand multi-instance gateways keep per-instance tables, the same limit this package has. |
| Findings | `FindingItem`, `RAD-*` ids, no free text, SQL-validated | `M42Finding` | Add a mapper, and a RedHand-side `kind` (for example `policy`) and rule-id family for CERT-In rules. That is a RedHand schema migration and needs their approval. |
| Modes | `off`, `observe`, `block` per control | `enforce`, `observe_only` | Map `observe` to `observe_only` and `block` to `enforce`; `off` skips the stage. |
| Audit | Black Box in core, one trail, hash-chained | Own hash-chained JSONL | Do not run a second ledger (RedHand's ADR 0030). Implement `AuditLogBackend` that forwards records to the Black Box, keeping `policy_sha256`; keep this package's file log for standalone use. |
| Human approval | Four-eyes HITL state machine in core, Telegram notifications | Signed per-transaction approvals, single-use nonces | Route `ApprovalRequest` into core's approval flow; the approver service signs, keys stay out of the agent. Needs core API work. |
| Telemetry | OpenTelemetry, Prometheus, OCSF 1.1.0 | `TelemetrySink` | Implement the sink on RedHand's existing paths; add nothing new. |
| Revocation | Freeze or revoke takes effect within 5 s | `RevocationStore` | Map freeze and revoke to the shield's quarantine and revocation registries so both agree. |
| Packaging | `uv` workspace, lockfile | wheel on PyPI (not yet published) | Adding a dependency to RedHand needs their approval; start with a path or workspace dependency. |

## What has to be decided before any RedHand code changes

These are choices the code cannot answer.

1. **Placement.** The adapter lives in RedHand (`agentwall/`, depending on this package) or here as
   an optional module. Recommendation: in RedHand, behind a kill switch, so the preset stays
   host-neutral.
2. **What "run" and "environment" mean** for a RedHand agent, since its tokens have neither.
3. **Who opts in.** The money rules are meaningless without bound payment tools; recommend a
   per-tenant, default-off control, in `observe` first.
4. **Schema change.** A new finding `kind` and rule-id family in core's SQL constraints is a
   migration; confirm RedHand accepts it, or whether to send CERT-In findings through an existing kind.

## Next

A plan in RedHand's own format (goal, current state, approach with a rejected alternative, changes,
security impact, migrations, tests, cost, risks) for the smallest vertical slice: an opt-in,
observe-only shield stage in the gateway, with the mapper and Black Box backend. It is written and
approved before any code in RedHand changes.
