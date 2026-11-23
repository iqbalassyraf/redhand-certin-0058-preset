# redhand-certin-0058-preset

A deterministic, fail-closed runtime interceptor for AI-agent tool calls in fintech and BFSI
environments, built against CERT-In advisories **CIAD-2026-0058** (CRAFTY FALCON) and
**CIAD-2026-0049** (AI agents as attack vectors). It sits on the tool-execution boundary, so a
manipulated agent cannot reach a payment tool except through it. **No model is in the decision
path.**

## Start here

1. [Quickstart](quickstart.md): from `pip install` to a protected agent in about two minutes.
2. [Architecture](architecture.md): how a call flows through the shield.
3. [Threat model](threat-model.md): what is defended, and what is not.
   [Comparison](comparison.md) explains why enforcement sits at the execution layer.
4. [Rule catalog](rules.md): every rule, its severity, and whether it can be tuned or waived.
5. [Integration](../README.md#integrating-with-a-host-application): manifest, schemas, key
   rotation, shared detector state.
6. [Detection results](detection-results.md): the replay corpus numbers, regenerated from the repo.

## What it gives you

- **Pinned identity:** Ed25519 run tokens bound to one run, one environment and a fixed tool list.
- **Behavioural breakers:** micro-transaction probing, velocity, recon-to-payment sequences,
  structuring across runs, payees and currencies, rolling cumulative caps.
- **Human approval where it counts:** per-transaction signed approvals with single-use nonces.
- **Evidence:** a SHA-256 hash-chained audit log, verifiable offline, plus an HTML evidence report.
- **A safe rollout path:** observe-only mode records `would_have_blocked` before you enforce.

## Honest limits

It is an in-process control: a host that is fully compromised can bypass it, so run tools behind
the out-of-process gateway or a sandbox. The [threat model](threat-model.md) lists every limit.
