# Architecture

The shield sits on the tool-execution boundary. The agent, and anything that has manipulated
the agent, can only reach a tool through it. **No model is in the decision path**: every
decision is a pure function of the signed token, the declarative policy, the clock and
sliding-window state.

<svg viewBox="0 0 760 330" role="img" aria-label="A tool call flows through four stages and either reaches the tool or is blocked; every decision is written to a hash-chained audit log" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="ah"/></marker>
  </defs>
  <rect x="10" y="20" width="110" height="60" rx="8" class="box"/>
  <text x="65" y="46" class="t" text-anchor="middle">Agent</text>
  <text x="65" y="64" class="s" text-anchor="middle">tool call + ctx</text>
  <rect x="160" y="10" width="440" height="190" rx="10" class="core"/>
  <text x="380" y="32" class="t" text-anchor="middle">Shield decision core</text>
  <rect x="176" y="46" width="98" height="64" rx="6" class="box"/>
  <text x="225" y="68" class="t" text-anchor="middle">1 Quarantine</text>
  <text x="225" y="86" class="s" text-anchor="middle">run, subject</text>
  <rect x="284" y="46" width="98" height="64" rx="6" class="box"/>
  <text x="333" y="68" class="t" text-anchor="middle">2 Identity</text>
  <text x="333" y="86" class="s" text-anchor="middle">token, env, pins</text>
  <rect x="392" y="46" width="98" height="64" rx="6" class="box"/>
  <text x="441" y="68" class="t" text-anchor="middle">3 Off-hours</text>
  <text x="441" y="86" class="s" text-anchor="middle">tighten limits</text>
  <rect x="500" y="46" width="90" height="64" rx="6" class="box"/>
  <text x="545" y="68" class="t" text-anchor="middle">4 Gates</text>
  <text x="545" y="86" class="s" text-anchor="middle">+ detectors</text>
  <text x="380" y="140" class="s" text-anchor="middle">detectors: micro-probe, velocity, sequence, structuring, caps</text>
  <text x="380" y="160" class="s" text-anchor="middle">gates: HITL threshold, new beneficiary, signed approvals</text>
  <text x="380" y="180" class="s" text-anchor="middle">state: WindowStore (in memory, or the host's backend)</text>
  <rect x="640" y="20" width="110" height="60" rx="8" class="ok"/>
  <text x="695" y="46" class="t" text-anchor="middle">Tool runs</text>
  <text x="695" y="64" class="s" text-anchor="middle">allow / step-up ok</text>
  <rect x="640" y="130" width="110" height="60" rx="8" class="bad"/>
  <text x="695" y="156" class="t" text-anchor="middle">Blocked</text>
  <text x="695" y="174" class="s" text-anchor="middle">typed exception</text>
  <rect x="160" y="240" width="590" height="70" rx="10" class="box"/>
  <text x="455" y="266" class="t" text-anchor="middle">Hash-chained audit log (SHA-256, offline verifier) + quarantine registry</text>
  <text x="455" y="288" class="s" text-anchor="middle">every decision, allowed or blocked, is recorded with the policy fingerprint</text>
  <path d="M120 50H160" class="ln" marker-end="url(#arr)"/>
  <path d="M600 50H640" class="ln" marker-end="url(#arr)"/>
  <path d="M600 160H640" class="ln" marker-end="url(#arr)"/>
  <path d="M380 200V240" class="ln" marker-end="url(#arr)"/>
</svg>

## The four stages

1. **Quarantine.** A run, or every run of a token subject, that tripped a breaker is refused
   before anything else is evaluated. This also stops an attacker from flooding the log.
2. **Identity.** The Ed25519 run token must verify, belong to this run, name the audience, be
   unrevoked and unexpired. Its environment must equal the call's `target_env`, and the tool
   must be in the signed `allowed_tools`. This is the staging-to-prod pivot check.
3. **Off-hours.** On weekends, holidays and outside business hours the policy is tightened
   as a pure function of policy and clock: limits halve and approval becomes mandatory.
4. **Gates and detectors.** Stateless approval gates, then the sliding-window detectors under
   a short lock. Detector state lives behind the `WindowStore` protocol.

Enforce mode stops the call with a typed exception that carries the finding. Observe-only
mode lets it through but records `would_have_blocked`, so a policy can be rolled out safely.

## Where each piece lives

| Concern | Module |
|---|---|
| Decision core, `@redhand_guard` | `interceptor.py` |
| Tokens, keyring, audience | `crypto.py`, `models.py` |
| Detectors and window state | `detectors.py`, `windowstore.py` |
| Policy loading, overlays, exemptions | `layers.py`, `models.py` |
| Per-transaction approvals | `approvals.py` |
| Audit chain and verifier | `audit.py` |
| Revocation and quarantine journals | `revocations.py` |
| Host contract: manifest, schemas, fingerprint | `manifest.py`, `schemas.py`, `fingerprint.py` |
| Proof: replay, report, doctor | `replay.py`, `report.py`, `diagnostics.py` |

## Fail closed

A missing or malformed context, an unverifiable token, a full detector table or a store error
all produce a block, never a silent allow. The [threat model](threat-model.md) lists what is
defended and, just as important, what is not.
