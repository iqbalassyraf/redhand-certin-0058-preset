# Quickstart: from `pip install` to a protected agent

About two minutes. Every code block marked `python` or `bash run` below is executed by the
test suite (`tests/test_quickstart.py`), so this page cannot drift from the package.

## 1. Install

```bash
pip install redhand-certin-0058-preset
```

Python 3.11 or newer. The decision path makes no network calls.

## 2. Protect a tool

A *run token* is an Ed25519-signed grant naming the environment, the single agent run and the
tools that run may call. The shield checks it on every call, before your tool executes.

```python
from decimal import Decimal

from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    Env,
    HITLRequiredError,
    HashChainedAuditLog,
    Shield,
    ToolCallContext,
    load_policy,
    redhand_guard,
)

private, public = AgentTokenIssuer.generate_keypair()
audit = HashChainedAuditLog("audit.jsonl")
shield = Shield(load_policy(), AgentTokenVerifier(public), audit=audit)


@redhand_guard(shield)
def settle_merchant(merchant_id: str, *, ctx: ToolCallContext) -> str:
    return f"settled {merchant_id}"


token = AgentTokenIssuer(private).mint(
    subject="svc-settlement-agent",
    agent_run_id="run-1",
    env=Env.PROD,
    allowed_tools=["settle_merchant"],
    ttl_seconds=900,
)


def call(amount: str) -> str:
    ctx = ToolCallContext(
        agent_run_id="run-1",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token=token,
        amount=Decimal(amount),
        currency="USD",
    )
    return settle_merchant("m-1", ctx=ctx)
```

## 3. See it allow, then block

```python
print(call("25.00"))  # inside policy: the tool runs

try:
    call("25000")  # above USD 10,000 on a protected tool: needs a signed approval
except HITLRequiredError as exc:
    print("blocked:", exc.finding.rule_id)  # the tool body never ran

audit.close()
```

Expected output:

```text
settled m-1
blocked: CIAD-2026-0058.R3.hitl_required
```

## 4. Verify the evidence

Every decision, allowed or blocked, was appended to a SHA-256 hash chain. Verify it offline,
with no key and no network:

```bash run
redhand-shield verify-audit audit.jsonl
redhand-shield fingerprint
```

Edit any line of `audit.jsonl` and the first command fails at that line.

## Where next

- [Architecture](architecture.md): how a call flows through the shield.
- [Threat model](threat-model.md): what is and is not defended.
- [Integration](../README.md#integrating-with-a-host-application): manifest, schemas, key rotation,
  shared detector state.
- [Comparison](comparison.md): why enforcement at the execution layer.
