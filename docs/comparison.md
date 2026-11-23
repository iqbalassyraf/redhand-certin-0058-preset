# Execution-layer enforcement vs prompt-based guardrails

Two different things get called a "guardrail" for an AI agent that can move money:

- **A prompt-based guardrail** is an instruction, or a second model that reads the conversation, asking the agent not to do
  something: a system prompt, a policy written in natural language, a classifier or judge that
  screens inputs and outputs.
- **Execution-layer enforcement** is a deterministic check on the tool call itself, at the
  moment the agent tries to run it. This package is one: it verifies a signed token, applies a
  declarative policy to the arguments, and refuses the call before the tool body executes.

They are not rivals. They answer different questions. This page says what each can honestly
promise, and where this package stops.

## What each can guarantee

| Property | Prompt-based guardrail | Execution-layer enforcement (this package) |
|---|---|---|
| What it constrains | What the model is *asked* or *likely* to do | What a tool call is *allowed* to do |
| Decision | Probabilistic: a model's judgement | Deterministic: same inputs, same decision |
| Effect of prompt injection | The injected text is processed by the same kind of system the guardrail depends on, so it can be argued around | None: injected text cannot change a signature, a policy or a counter |
| If the agent is compromised or confused | The guardrail is part of what is compromised | The call still has to pass the check to reach the tool |
| Identity and scope | Stated in text | Cryptographic: Ed25519 token bound to one run, one environment and a fixed tool list |
| Behaviour over time | Judged per message, often without memory | Sliding windows across calls, runs, payees and currencies |
| Human approval | A request in the chat | A signed, single-use approval bound to one transaction |
| Evidence | A transcript | A hash-chained audit log that verifies offline and shows tampering |
| Latency and cost per call | A model call | In-process microseconds, no model, no network (see below) |
| Safe rollout | Hard to measure what it would have blocked | Observe-only mode records every `would_have_blocked` before you enforce |
| Understands intent and context | Yes, that is its strength | No: it sees fields, tokens and counters, not meaning |

The honest summary: a prompt-based guardrail can make a well-behaved agent behave better, and
it is good at things a rule cannot express. It cannot be the thing that stops a **manipulated**
agent from reaching a payment API, because it is advice, delivered to the party being attacked.
Enforcement at the execution layer is the floor that still holds when the advice is ignored.

## What this package does, with numbers you can reproduce

The replay corpus has 108 synthetic scenarios. 73 are attacks the preset should catch and 26 are
ordinary traffic. On that corpus the preset stops 73 of 73 attacks (every expected rule fired),
wrongly flags 0 of 26 benign scenarios, and has 5 documented gaps (attacks it does not catch, by
design) and 4 documented false positives, all listed in the
[detection results](detection-results.md).

**Read those numbers carefully.** The corpus is synthetic and written to exercise each rule. A
100% result on it is a regression check that every control does what it claims on the cases we
wrote down. It is not a measurement of how the preset would perform on real traffic, and it is not
a security guarantee.

Decision latency is measured, not claimed: the decision core takes a median of about 0.15 ms on
the machine that produced the benchmark table in the README, against a 2 ms budget. It is
machine-dependent, so run it yourself.

Reproduce both:

```bash
redhand-shield replay            # the corpus numbers above
python benchmarks/bench_latency.py   # latency on your hardware
```

## What enforcement does not do

Enforcement at the execution layer is not a complete defence. Specifically:

- **It trusts its own process and keys.** It runs inside the agent's process. An attacker with
  arbitrary code execution can bypass or patch it, and a stolen signing key mints valid tokens.
  Run tools behind the out-of-process gateway or a sandbox, and keep keys out of the agent.
- **It judges the fields you bind.** A tool that moves money through an argument nobody bound is
  not judged by the money rules. Bind protected tools and let them fail closed.
- **The first micro-probe is indistinguishable from a small legitimate payment.** The breaker
  trips on the second, as the advisory describes.
- **It has no sense of intent.** It cannot tell a legitimate large payment from a coerced one
  that stays inside policy. Human approval shows a person what is about to happen; the host must
  render that faithfully.
- **State is per process by default.** Several workers need a shared window store.

The [threat model](threat-model.md) lists these and the mitigations in full.

## Use both

- Keep the prompt-level guidance and any model-based screening you have. They catch the cases a
  rule cannot express and reduce how often the floor is hit.
- Put enforcement at the tool boundary for anything that moves money or changes access. It is
  cheap, deterministic, and still works on the day the model is talked into something.
- Roll it out in observe-only mode first, read the evidence report, then enforce.

This page makes no comparison with any named product. It compares two kinds of control.
