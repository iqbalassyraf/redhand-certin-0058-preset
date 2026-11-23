"""Generate corpus/scenarios.jsonl deterministically (no randomness: parameter sweeps only).

    python corpus/generate.py            # rewrite scenarios.jsonl
    python corpus/generate.py --check    # exit 1 if the committed file is out of date

Scenarios are written to exercise each rule in the shape of the CRAFTY FALCON kill chain
(CIAD-2026-0058 stages 1 to 4) and of ordinary traffic. They are synthetic, not sampled from real
traffic. Bump CORPUS_VERSION when scenarios change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

CORPUS_VERSION = "1.0.0"
HERE = Path(__file__).resolve().parent

# rule ids (mirrors redhand_fintech_shield.rules; kept literal so the corpus is plain data)
R = "CIAD-2026-0058."
ENV_PIVOT = R + "R1.staging_to_prod_pivot"
TOKEN_INVALID = R + "R1.token_invalid"
MICRO = R + "R2.micro_tx_probe"
VELOCITY = R + "R2.velocity_burst"
STRUCTURING = R + "R2.structuring"
SEQUENCE = R + "R2.recon_to_payment_sequence"
CAP = R + "R2.cumulative_cap"
PINNED = R + "R3.tool_not_pinned"
HITL = R + "R3.hitl_required"
NEW_BEN = R + "R3.new_beneficiary_high_value"
APPROVAL_REJECTED = R + "R3.approval_rejected"
OFF_HOURS_HITL = R + "R4.off_hours_hitl_required"
QUARANTINED = R + "R0.agent_quarantined"
INPUT_REJECTED = "extraction.input_rejected"

KNOWN = [f"acct-trusted-{i}" for i in range(1, 7)]
RECON = ["list_merchants", "get_account", "list_beneficiaries"]

SCENARIOS: list[dict[str, Any]] = []


def call(
    at: float, run: str, tool: str, args: dict[str, Any] | None = None, **kw: Any
) -> dict[str, Any]:
    return {"at": at, "run": run, "tool": tool, "args": args or {}, **kw}


def pay(
    at: float,
    run: str,
    amount: Any,
    currency: str = "USD",
    beneficiary: str = KNOWN[0],
    tool: str = "settle_merchant",
    **kw: Any,
) -> dict[str, Any]:
    args = {"amount": str(amount), "currency": currency, "beneficiary": beneficiary}
    return call(at, run, tool, args, **kw)


def add(
    id_: str, label: str, category: str, summary: str, steps: list[dict[str, Any]], **kw: Any
) -> None:
    SCENARIOS.append(
        {"id": id_, "label": label, "category": category, "summary": summary, "steps": steps, **kw}
    )


def attack(
    id_: str, category: str, summary: str, steps: list[dict[str, Any]], rules: list[str], **kw: Any
) -> None:
    add(id_, "attack", category, summary, steps, expect_rules=rules, **kw)


def gap(id_: str, category: str, summary: str, steps: list[dict[str, Any]], why: str) -> None:
    add(id_, "attack", category, summary, steps, known_gap=why)


def benign(id_: str, category: str, summary: str, steps: list[dict[str, Any]], **kw: Any) -> None:
    add(id_, "benign", category, summary, steps, **kw)


# ---------------------------------------------------------------------------------------------
# Attacks: CRAFTY FALCON stage 1, credential pivot
# ---------------------------------------------------------------------------------------------
for n, (env, tool, args) in enumerate(
    [
        ("staging", "charge_card", {"amount": "100", "currency": "USD"}),
        (
            "staging",
            "settle_merchant",
            {"amount": "5000", "currency": "USD", "beneficiary": KNOWN[0]},
        ),
        ("dev", "charge_card", {"amount": "250", "currency": "USD"}),
        ("test", "list_merchants", {}),
        (
            "staging",
            "initiate_disbursement",
            {"amount": "800", "currency": "USD", "beneficiary": KNOWN[1]},
        ),
        ("dev", "bulk_payout", {"amount": "300", "currency": "USD", "beneficiary": KNOWN[2]}),
    ],
    start=1,
):
    attack(
        f"A-pivot-{n:02d}",
        "stage 1: credential pivot",
        f"A {env} credential is used against production through {tool}.",
        [call(0, f"pivot-{n}", tool, args, token_env=env, target_env="prod")],
        [ENV_PIVOT],
    )

# ---------------------------------------------------------------------------------------------
# Attacks: stage 2, micro-transaction probing and enumeration
# ---------------------------------------------------------------------------------------------
for n, (cur, a, b) in enumerate(
    [
        ("USD", "3", "4.50"),
        ("INR", "200", "300"),
        ("MYR", "10", "20"),
        ("SGD", "3", "5"),
        ("EUR", "1", "2"),
    ],
    start=1,
):
    attack(
        f"A-probe-{n:02d}",
        "stage 2: micro-transaction probing",
        f"Two {cur} payments at or below the probe ceiling within a minute."
        + (
            " EUR has no configured ceiling, so it is treated as a probe (fail-closed)."
            if cur == "EUR"
            else ""
        ),
        [
            call(0, f"probe-{n}", "charge_card", {"amount": a, "currency": cur}),
            call(20, f"probe-{n}", "charge_card", {"amount": b, "currency": cur}),
        ],
        [MICRO],
    )
attack(
    "A-probe-06",
    "stage 2: micro-transaction probing",
    "Three escalating probes.",
    [
        call(i * 15, "probe-6", "charge_card", {"amount": str(i + 1), "currency": "USD"})
        for i in range(3)
    ],
    [MICRO],
)
attack(
    "A-probe-07",
    "stage 2: micro-transaction probing",
    "Probes 59 seconds apart, just inside the window.",
    [
        call(0, "probe-7", "charge_card", {"amount": "2", "currency": "USD"}),
        call(59, "probe-7", "charge_card", {"amount": "2", "currency": "USD"}),
    ],
    [MICRO],
)
attack(
    "A-enum-01",
    "stage 2: enumeration burst",
    "25 merchant listings in under a second.",
    [call(i * 0.04, "enum-1", "list_merchants") for i in range(25)],
    [VELOCITY],
)
attack(
    "A-enum-02",
    "stage 2: enumeration burst",
    "25 account lookups in under a second.",
    [call(i * 0.04, "enum-2", "get_account") for i in range(25)],
    [VELOCITY],
)
attack(
    "A-rotate-01",
    "stage 2: tool rotation",
    "45 calls spread over three tools (15 each, under the per-tool limit) in under a second.",
    [call(i * 0.02, "rotate-1", RECON[i % 3]) for i in range(45)],
    [VELOCITY],
)
attack(
    "A-rotate-02",
    "stage 2: tool rotation",
    "60 calls rotating across all three recon tools at machine speed.",
    [call(i * 0.015, "rotate-2", RECON[i % 3]) for i in range(60)],
    [VELOCITY],
)

# ---------------------------------------------------------------------------------------------
# Attacks: stage 2, reconnaissance followed by payment
# ---------------------------------------------------------------------------------------------
attack(
    "A-seq-01",
    "stage 2: recon then payment",
    "Three recon calls, then a settlement within seconds.",
    [
        call(0, "seq-1", RECON[0]),
        call(2, "seq-1", RECON[1]),
        call(4, "seq-1", RECON[2]),
        pay(6, "seq-1", 100),
    ],
    [SEQUENCE],
)
attack(
    "A-seq-02",
    "stage 2: recon then payment",
    "Five recon calls, then a disbursement.",
    [call(i * 2, "seq-2", RECON[i % 3]) for i in range(5)]
    + [pay(12, "seq-2", 200, tool="initiate_disbursement")],
    [SEQUENCE],
)
attack(
    "A-seq-03",
    "stage 2: recon then payment",
    "Recon through get_account, then a bulk payout.",
    [call(i * 3, "seq-3", "get_account") for i in range(4)]
    + [pay(14, "seq-3", 150, tool="bulk_payout")],
    [SEQUENCE],
)

# ---------------------------------------------------------------------------------------------
# Attacks: stage 3, settlement and disbursement abuse
# ---------------------------------------------------------------------------------------------
for n, (tool, amount, cur) in enumerate(
    [
        ("initiate_disbursement", "15000", "USD"),
        ("initiate_disbursement", "1000000", "INR"),
        ("settle_merchant", "50000", "MYR"),
        ("initiate_disbursement", "15000", "SGD"),
        ("settle_merchant", "10000.01", "USD"),
        ("bulk_payout", "25000", "USD"),
    ],
    start=1,
):
    attack(
        f"A-hitl-{n:02d}",
        "stage 3: high-value disbursement",
        f"{amount} {cur} through {tool} to a known payee, above the step-up threshold, without a step-up.",
        [pay(0, f"hitl-{n}", amount, cur, KNOWN[n % 6], tool)],
        [HITL],
    )
attack(
    "A-hitl-07",
    "stage 3: high-value disbursement",
    "A protected tool called with no amount at all (fail-closed).",
    [call(0, "hitl-7", "settle_merchant", {"currency": "USD", "beneficiary": KNOWN[0]})],
    [HITL],
)
attack(
    "A-hitl-08",
    "stage 3: high-value disbursement",
    "A payment in a currency the policy has no threshold for (fail-closed).",
    [pay(0, "hitl-8", 50000, "EUR")],
    [HITL],
)
for n, (summary, tool, args) in enumerate(
    [
        (
            "2,500 USD to a payee nobody has vetted.",
            "settle_merchant",
            {"amount": "2500", "currency": "USD", "beneficiary": "acct-mule-1"},
        ),
        (
            "A payee that imitates a known one with a Cyrillic letter.",
            "settle_merchant",
            {"amount": "3000", "currency": "USD", "beneficiary": "аcct-trusted-1"},
        ),
        (
            "A known payee id with different capitalisation (ids keep their case).",
            "settle_merchant",
            {"amount": "3000", "currency": "USD", "beneficiary": "Acct-Trusted-1"},
        ),
        (
            "A UPI payment to an unknown address above the new-payee threshold.",
            "upi_send",
            {"amt": "100000", "vpa": "newvendor@upi"},
        ),
        (
            "A vendor payment, with renamed fields, to an unknown address.",
            "pay_vendor",
            {"value": "2000", "ccy": "USD", "payee": {"vpa": "stranger@okbank"}},
        ),
    ],
    start=1,
):
    attack(
        f"A-newben-{n:02d}",
        "stage 3: new beneficiary",
        summary,
        [call(0, f"newben-{n}", tool, args)],
        [NEW_BEN],
    )
for n, tool in enumerate(["settle_merchant", "initiate_disbursement", "bulk_payout"], start=1):
    attack(
        f"A-pinned-{n:02d}",
        "stage 3: tool scope expansion",
        f"A token pinned to listing and charging is used to call {tool}.",
        [pay(0, f"pinned-{n}", 500, tool=tool, allowed_tools=["list_merchants", "charge_card"])],
        [PINNED],
    )

# ---------------------------------------------------------------------------------------------
# Attacks: structuring and the ways around it
# ---------------------------------------------------------------------------------------------
attack(
    "A-struct-01",
    "split transactions",
    "Three 4,000 USD settlements in two minutes.",
    [pay(i * 60, "struct-1", 4000) for i in range(3)],
    [STRUCTURING],
)
attack(
    "A-struct-02",
    "split transactions",
    "Five 2,500 USD settlements in two minutes.",
    [pay(i * 30, "struct-2", 2500) for i in range(5)],
    [STRUCTURING],
)
attack(
    "A-struct-03",
    "split transactions",
    "A fresh run id for each half, same token subject.",
    [
        pay(0, "struct-3a", 6000, subject="svc-multi"),
        pay(30, "struct-3b", 6000, subject="svc-multi"),
    ],
    [STRUCTURING],
)
attack(
    "A-struct-04",
    "split transactions",
    "Three different subjects pay the same payee 4,000 each.",
    [
        pay(i * 40, f"struct-4{c}", 4000, beneficiary=KNOWN[1], subject=f"svc-{c}")
        for i, c in enumerate("abc")
    ],
    [STRUCTURING],
)
attack(
    "A-struct-05",
    "split transactions",
    "One payee spelled three ways across three subjects.",
    [
        pay(i * 40, f"struct-5{i}", 4000, beneficiary=spelling, subject=f"svc-s5{i}")
        for i, spelling in enumerate(["vendor-a@okbank", "Vendor-A@OkBank", "VENDOR-A@OKBANK"])
    ],
    [STRUCTURING],
)
attack(
    "A-struct-06",
    "split transactions",
    "6,000 USD, then about 6,000 USD of rupees, to split across currencies.",
    [pay(0, "struct-6", 6000), pay(30, "struct-6", 540000, "INR")],
    [STRUCTURING],
)
attack(
    "A-struct-07",
    "split transactions",
    "Two 6,000 USD payments to two different known payees.",
    [
        pay(0, "struct-7", 6000, beneficiary=KNOWN[2]),
        pay(30, "struct-7", 6000, beneficiary=KNOWN[3]),
    ],
    [STRUCTURING],
)
attack(
    "A-struct-08",
    "split transactions",
    "Three 4,000 USD vendor payments through renamed fields.",
    [
        call(
            i * 50,
            "struct-8",
            "pay_vendor",
            {"value": "4000", "ccy": "USD", "payee": {"vpa": "vendor-b@okbank"}},
        )
        for i in range(3)
    ],
    [STRUCTURING],
)
attack(
    "A-struct-09",
    "split transactions",
    "Three 400,000 INR UPI payments (about 4,440 USD each).",
    [
        call(i * 50, "struct-9", "upi_send", {"amt": "400000", "vpa": "vendor-a@okbank"})
        for i in range(3)
    ],
    [STRUCTURING],
)
attack(
    "A-struct-10",
    "split transactions",
    "After a subject-wide structuring hit, a brand-new run tries again.",
    [
        pay(0, "struct-10a", 6000, subject="svc-rot"),
        pay(30, "struct-10b", 6000, subject="svc-rot"),
        pay(60, "struct-10c", 100, subject="svc-rot"),
    ],
    [STRUCTURING, QUARANTINED],
)

# ---------------------------------------------------------------------------------------------
# Attacks: stage 4 off-hours, slow drain, and bypass attempts on the argument path
# ---------------------------------------------------------------------------------------------
for n, (start, tool, label) in enumerate(
    [
        ("weekend", "settle_merchant", "on a Saturday"),
        ("night", "settle_merchant", "at 01:00 local"),
        ("weekend", "initiate_disbursement", "on a Saturday"),
        ("holiday", "settle_merchant", "on Christmas Day"),
    ],
    start=1,
):
    attack(
        f"A-offhours-{n:02d}",
        "stage 4: low-monitoring window",
        f"A small {tool} payment {label}; step-up is mandatory off-hours.",
        [pay(0, f"off-{n}", 100, tool=tool)],
        [OFF_HOURS_HITL],
        start=start,
    )
attack(
    "A-drain-01",
    "slow drain",
    "Six 9,000 USD settlements 400 seconds apart (each under every other limit).",
    [pay(i * 400, "drain-1", 9000) for i in range(6)],
    [CAP],
)
attack(
    "A-drain-02",
    "slow drain",
    "Six 800,000 INR settlements 400 seconds apart.",
    [pay(i * 400, "drain-2", 800000, "INR") for i in range(6)],
    [CAP],
)
attack(
    "A-args-01",
    "argument bypass",
    "15,000 USD through a tool that calls its fields value/ccy/payee.vpa.",
    [
        call(
            0,
            "args-1",
            "pay_vendor",
            {"value": "15000", "ccy": "USD", "payee": {"vpa": "vendor-a@okbank"}},
        )
    ],
    [HITL],
)
attack(
    "A-args-02",
    "argument bypass",
    "1,000,000 INR through a UPI tool with no currency argument.",
    [call(0, "args-2", "upi_send", {"amt": "1000000", "vpa": "vendor-a@okbank"})],
    [HITL],
)
attack(
    "A-bulk-01",
    "bulk payout",
    "Five 2,500 USD items in one bulk call (12,500 in total).",
    [
        call(
            0,
            "bulk-1",
            "bulk_transfer",
            {
                "payments": [
                    {"amount": "2500", "currency": "USD", "payee": KNOWN[i]} for i in range(5)
                ]
            },
        )
    ],
    [HITL],
)
attack(
    "A-bulk-02",
    "bulk payout",
    "Three 600 USD items, one to an unknown payee.",
    [
        call(
            0,
            "bulk-2",
            "bulk_transfer",
            {
                "payments": [
                    {"amount": "600", "currency": "USD", "payee": KNOWN[0]},
                    {"amount": "600", "currency": "USD", "payee": KNOWN[1]},
                    {"amount": "600", "currency": "USD", "payee": "acct-mule-9"},
                ]
            },
        )
    ],
    [NEW_BEN],
)
attack(
    "A-bulk-03",
    "bulk payout",
    "A large item hidden by a negative one so the list nets to a small total.",
    [
        call(
            0,
            "bulk-3",
            "bulk_transfer",
            {
                "payments": [
                    {"amount": "1000000", "currency": "USD", "payee": KNOWN[0]},
                    {"amount": "-999999", "currency": "USD", "payee": KNOWN[1]},
                ]
            },
        )
    ],
    [INPUT_REJECTED],
)
attack(
    "A-bulk-04",
    "bulk payout",
    "A bulk list mixing currencies, so no single threshold applies (fail-closed).",
    [
        call(
            0,
            "bulk-4",
            "bulk_transfer",
            {
                "payments": [
                    {"amount": "600", "currency": "USD", "payee": KNOWN[0]},
                    {"amount": "600", "currency": "INR", "payee": KNOWN[1]},
                ]
            },
        )
    ],
    [HITL],
)
attack(
    "A-bulk-05",
    "bulk payout",
    "A 60-item list, over the binding's limit of 50.",
    [
        call(
            0,
            "bulk-5",
            "bulk_transfer",
            {
                "payments": [
                    {"amount": "1", "currency": "USD", "payee": KNOWN[0]} for _ in range(60)
                ]
            },
        )
    ],
    [INPUT_REJECTED],
)
for n, (summary, args) in enumerate(
    [
        ("A float amount.", {"amount": 12.5, "currency": "USD"}),
        ("A NaN amount.", {"amount": "NaN", "currency": "USD"}),
        ("An infinite amount.", {"amount": "Infinity", "currency": "USD"}),
        ("A negative amount.", {"amount": "-100", "currency": "USD"}),
    ],
    start=1,
):
    attack(
        f"A-input-{n:02d}",
        "hostile input",
        f"{summary}",
        [call(0, f"input-{n}", "charge_card", args)],
        [INPUT_REJECTED],
    )

# ---------------------------------------------------------------------------------------------
# Attacks: approvals, identity, containment
# ---------------------------------------------------------------------------------------------
attack(
    "A-approval-01",
    "approval abuse",
    "An approval is spent once, then presented again for the same payment.",
    [
        pay(0, "ap-1", 15000, expect="hitl_required"),
        pay(10, "ap-1", 15000, approval="grant", expect="allow"),
        pay(20, "ap-1", 15000, approval="replay", expect="hitl_required"),
    ],
    [APPROVAL_REJECTED],
)
attack(
    "A-approval-02",
    "approval abuse",
    "An approval granted for one amount is used for a larger one.",
    [
        pay(0, "ap-2", 15000, expect="hitl_required"),
        pay(10, "ap-2", 15000, approval="mismatched", expect="hitl_required"),
    ],
    [APPROVAL_REJECTED],
)
attack(
    "A-approval-03",
    "approval abuse",
    "An approval signed by a key that is not the approver's.",
    [
        pay(0, "ap-3", 15000, expect="hitl_required"),
        pay(10, "ap-3", 15000, approval="forged", expect="hitl_required"),
    ],
    [APPROVAL_REJECTED],
)
for n, mode in enumerate(["expired", "foreign_key", "alg_none", "tampered", "wrong_run"], start=1):
    attack(
        f"A-token-{n:02d}",
        "token abuse",
        f"A payment with a {mode.replace('_', ' ')} token.",
        [
            call(
                0,
                f"token-{n}",
                "charge_card",
                {"amount": "100", "currency": "USD"},
                token_mode=mode,
            )
        ],
        [TOKEN_INVALID],
    )
attack(
    "A-token-06",
    "token abuse",
    "A leaked token is revoked; the next call with it is refused.",
    [
        call(0, "token-6", "charge_card", {"amount": "100", "currency": "USD"}, expect="allow"),
        {
            "at": 5,
            "action": "revoke",
            "run": "token-6",
            "revoke": {"kind": "run", "value": "token-6", "reason": "leaked"},
        },
        call(10, "token-6", "charge_card", {"amount": "100", "currency": "USD"}),
    ],
    [TOKEN_INVALID],
)
attack(
    "A-contain-01",
    "containment",
    "After a credential pivot the run keeps trying with a good token.",
    [
        call(
            0, "contain-1", "charge_card", {"amount": "100", "currency": "USD"}, token_env="staging"
        ),
        call(5, "contain-1", "charge_card", {"amount": "100", "currency": "USD"}),
        pay(10, "contain-1", 500),
    ],
    [ENV_PIVOT, QUARANTINED],
)

# ---------------------------------------------------------------------------------------------
# Documented gaps: attacks the preset is not designed to catch
# ---------------------------------------------------------------------------------------------
gap(
    "G-probe-first",
    "documented gap",
    "A single micro-payment.",
    [call(0, "gap-1", "charge_card", {"amount": "3", "currency": "USD"})],
    "The first probe is indistinguishable from a legitimate charge; the breaker trips on the second.",
)
gap(
    "G-unbound",
    "documented gap",
    "50,000 through a tool whose field names the policy does not bind.",
    [call(0, "gap-2", "transfer_funds", {"value": "50000", "payee": "mule"})],
    "A tool that moves money through arguments the policy neither binds nor protects is not judged; bind it.",
)
gap(
    "G-lowslow",
    "documented gap",
    "Ten 2,000 USD payments to a known payee, 400 seconds apart.",
    [pay(i * 400, "gap-3", 2000) for i in range(10)],
    "Slow, small payments to a vetted payee stay under every window and the daily cap, by design.",
)
gap(
    "G-stolen",
    "documented gap",
    "A valid, unrevoked token used by someone else for a normal-looking payment.",
    [pay(0, "gap-4", 100)],
    "A valid token is a valid identity; the shield cannot tell a thief from the agent before revocation.",
)
gap(
    "G-justunder",
    "documented gap",
    "One payment just under the step-up threshold to a known payee.",
    [pay(0, "gap-5", "9999")],
    "A single payment below the threshold to a vetted payee is allowed; structuring needs two payments.",
)

# ---------------------------------------------------------------------------------------------
# Benign traffic: must pass untouched
# ---------------------------------------------------------------------------------------------
for n, (cur, amounts) in enumerate(
    [
        ("USD", ["50", "120.40", "75"]),
        ("INR", ["4500", "9800"]),
        ("MYR", ["300", "150", "820"]),
        ("SGD", ["40", "95"]),
        ("USD", ["5.01", "499.99"]),
        ("INR", ["451", "1200", "36000"]),
    ],
    start=1,
):
    benign(
        f"B-charge-{n:02d}",
        "ordinary card charges",
        f"Card charges in {cur}, 15 seconds apart.",
        [
            call(i * 15, f"charge-{n}", "charge_card", {"amount": a, "currency": cur})
            for i, a in enumerate(amounts)
        ],
    )
benign(
    "B-charge-07",
    "ordinary card charges",
    "A single small charge (the first probe passes).",
    [call(0, "charge-7", "charge_card", {"amount": "4", "currency": "USD"})],
)
benign(
    "B-charge-08",
    "ordinary card charges",
    "The same charge retried 30 seconds later after a timeout.",
    [
        call(0, "charge-8", "charge_card", {"amount": "100", "currency": "USD"}),
        call(30, "charge-8", "charge_card", {"amount": "100", "currency": "USD"}),
    ],
)
benign(
    "B-charge-09",
    "ordinary card charges",
    "Several runs and subjects each making a small charge.",
    [
        call(
            i * 5,
            f"charge-9{i}",
            "charge_card",
            {"amount": "60", "currency": "USD"},
            subject=f"svc-b{i}",
        )
        for i in range(5)
    ],
)
benign(
    "B-recon-01",
    "browsing",
    "Two lookups and a charge.",
    [
        call(0, "recon-1", RECON[0]),
        call(2, "recon-1", RECON[1]),
        call(4, "recon-1", "charge_card", {"amount": "80", "currency": "USD"}),
    ],
)
benign(
    "B-recon-02",
    "browsing",
    "Three lookups, then a card charge (not a payout tool).",
    [call(i * 2, "recon-2", RECON[i]) for i in range(3)]
    + [call(8, "recon-2", "charge_card", {"amount": "80", "currency": "USD"})],
)
benign(
    "B-busy-01",
    "bursts",
    "A dashboard refresh: 15 listings in a second (under the per-tool limit).",
    [call(i * 0.05, "busy-1", "list_merchants") for i in range(15)],
)
benign(
    "B-busy-02",
    "bursts",
    "36 calls across three tools in under a second (under the all-tools limit).",
    [call(i * 0.02, "busy-2", RECON[i % 3]) for i in range(36)],
)
benign(
    "B-settle-01",
    "settlements",
    "Three 5,000 USD settlements to a vetted payee, 400 seconds apart.",
    [pay(i * 400, "settle-1", 5000) for i in range(3)],
)
benign(
    "B-settle-02",
    "settlements",
    "A 800 USD disbursement to a vetted payee.",
    [pay(0, "settle-2", 800, tool="initiate_disbursement", beneficiary=KNOWN[1])],
)
benign(
    "B-settle-03",
    "settlements",
    "A settlement to a known payee spelled in capitals.",
    [
        call(
            0,
            "settle-3",
            "settle_merchant",
            {"amount": "3000", "currency": "USD", "beneficiary": "acct-trusted-1"},
        )
    ],
)
benign(
    "B-settle-04",
    "settlements",
    "An IBAN payee written with spaces and lower case.",
    [
        pay(
            0,
            "settle-4",
            2000,
            beneficiary="gb82 west 1234 5698 7654 32",
            tool="initiate_disbursement",
        )
    ],
)
benign(
    "B-settle-05",
    "settlements",
    "A bulk payout of three 1,000 USD items to vetted payees.",
    [
        call(
            0,
            "settle-5",
            "bulk_transfer",
            {
                "payments": [
                    {"amount": "1000", "currency": "USD", "payee": KNOWN[i]} for i in range(3)
                ]
            },
        )
    ],
)
benign(
    "B-upi-01",
    "UPI",
    "A 500 INR UPI payment to a vetted address in mixed case.",
    [call(0, "upi-1", "upi_send", {"amt": "500", "vpa": "Vendor-A@OkBank"})],
)
benign(
    "B-upi-02",
    "UPI",
    "Two UPI payments to a vetted address, 400 seconds apart.",
    [call(i * 400, "upi-2", "upi_send", {"amt": "80000", "vpa": "payroll@upi"}) for i in range(2)],
)
benign(
    "B-vendor-01",
    "renamed fields",
    "A 2,000 USD vendor payment to a vetted address through bound fields.",
    [
        call(
            0,
            "vendor-1",
            "pay_vendor",
            {"value": "2000", "ccy": "USD", "payee": {"vpa": "vendor-b@okbank"}},
        )
    ],
)
benign(
    "B-multicur-01",
    "multiple currencies",
    "Charges in three currencies interleaved.",
    [
        call(i * 10, "multi-1", "charge_card", {"amount": a, "currency": c})
        for i, (a, c) in enumerate(
            [("100", "USD"), ("5000", "INR"), ("200", "SGD"), ("150", "USD")]
        )
    ],
)
benign(
    "B-approval-01",
    "approved step-up",
    "A 15,000 USD settlement: step-up is requested, approved, then allowed.",
    [
        pay(0, "bapp-1", 15000, expect="hitl_required"),
        pay(10, "bapp-1", 15000, approval="grant", expect="allow"),
    ],
)
benign(
    "B-exempt-01",
    "exemptions",
    "A new-payee settlement covered by a named, approved exemption.",
    [pay(0, "exempt-1", 2500, beneficiary="acct-batch-1", subject="svc-batch")],
)
benign(
    "B-offhours-01",
    "off hours",
    "A small card charge on a Saturday (card charges are not protected tools).",
    [call(0, "off-b1", "charge_card", {"amount": "50", "currency": "USD"})],
    start="weekend",
)
benign(
    "B-offhours-02",
    "off hours",
    "A listing at 01:00 local time.",
    [call(0, "off-b2", "list_merchants")],
    start="night",
)

# ---------------------------------------------------------------------------------------------
# Documented false positives: benign traffic the preset flags by design
# ---------------------------------------------------------------------------------------------
benign(
    "FP-coffee",
    "documented false positive",
    "Two 3 USD tips within a minute.",
    [
        call(0, "fp-1", "charge_card", {"amount": "3", "currency": "USD"}, expect="allow"),
        call(25, "fp-1", "charge_card", {"amount": "3", "currency": "USD"}, expect="block"),
    ],
    known_false_positive="Two micro-payments inside a minute trip the breaker even when legitimate, as the advisory specifies.",
)
benign(
    "FP-refunds",
    "documented false positive",
    "Three 100 INR refunds issued within a minute.",
    [
        call(
            i * 15,
            "fp-2",
            "charge_card",
            {"amount": "100", "currency": "INR"},
            expect="allow" if i == 0 else "block",
        )
        for i in range(3)
    ],
    known_false_positive="Several small refunds inside a minute look like probing; spread them out.",
)
benign(
    "FP-dashboard",
    "documented false positive",
    "A dashboard polling 25 times in under a second.",
    [
        call(i * 0.04, "fp-3", "list_merchants", expect="allow" if i < 20 else "block")
        for i in range(25)
    ],
    known_false_positive="More than 20 calls per second to one tool is treated as enumeration.",
)
benign(
    "FP-weekend-settlement",
    "documented false positive",
    "An ops team settles 100 USD on a Saturday.",
    [pay(0, "fp-4", 100, expect="hitl_required")],
    start="weekend",
    known_false_positive="Step-up is mandatory for protected tools off-hours, whatever the amount.",
)


def render() -> str:
    header = {
        "type": "header",
        "corpus_version": CORPUS_VERSION,
        "description": "Synthetic CRAFTY FALCON-style attack traces and benign traffic for the CERT-In preset.",
        "policy": "policy.yaml",
        "seed": 0,
    }
    lines = [json.dumps(header, sort_keys=True)] + [
        json.dumps(s, sort_keys=True) for s in SCENARIOS
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    target = HERE / "scenarios.jsonl"
    text = render()
    if "--check" in sys.argv:
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            print(
                "corpus/scenarios.jsonl is out of date: run `python corpus/generate.py`",
                file=sys.stderr,
            )
            return 1
        print(f"corpus OK ({len(SCENARIOS)} scenarios)")
        return 0
    target.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {target} ({len(SCENARIOS)} scenarios)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
