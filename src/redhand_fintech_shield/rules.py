"""Stable rule identifiers and which of them policy may change.

Kept free of imports so both ``models`` (which validates policy against it) and ``detectors``
(which emits the rules) can use it without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Stable rule identifiers, namespaced by advisory and kill-chain stage.
R_QUARANTINED = "CIAD-2026-0058.R0.agent_quarantined"
R_TOKEN_INVALID = "CIAD-2026-0058.R1.token_invalid"  # noqa: S105 - rule id, not a credential
R_ENV_PIVOT = "CIAD-2026-0058.R1.staging_to_prod_pivot"
R_MICRO_TX = "CIAD-2026-0058.R2.micro_tx_probe"
R_VELOCITY = "CIAD-2026-0058.R2.velocity_burst"
R_STRUCTURING = "CIAD-2026-0058.R2.structuring"
R_SEQUENCE = "CIAD-2026-0058.R2.recon_to_payment_sequence"
R_TOOL_NOT_PINNED = "CIAD-2026-0058.R3.tool_not_pinned"
R_HITL = "CIAD-2026-0058.R3.hitl_required"
R_NEW_BENEFICIARY = "CIAD-2026-0058.R3.new_beneficiary_high_value"
R_OFF_HOURS_HITL = "CIAD-2026-0058.R4.off_hours_hitl_required"
R_OFF_HOURS = "CIAD-2026-0058.R4.off_hours_tightened"
R_CUMULATIVE_CAP = "CIAD-2026-0058.R2.cumulative_cap"
R_APPROVAL_ACCEPTED = "CIAD-2026-0058.R3.approval_accepted"
R_APPROVAL_REJECTED = "CIAD-2026-0058.R3.approval_rejected"
R_LEGACY_STEP_UP = "CIAD-2026-0058.R3.legacy_run_wide_step_up"
R_EXEMPTION_APPLIED = "CIAD-2026-0058.R3.exemption_applied"

# Detector rules an operator may run in shadow mode, disable, or re-label. Identity, token,
# tool-pinning, quarantine and approval rules are deliberately absent: they are not tunable.
OVERRIDABLE_RULES: frozenset[str] = frozenset(
    {
        R_MICRO_TX,
        R_VELOCITY,
        R_STRUCTURING,
        R_SEQUENCE,
        R_HITL,
        R_OFF_HOURS_HITL,
        R_NEW_BENEFICIARY,
        R_CUMULATIVE_CAP,
    }
)

# Rules a time-limited exemption may waive: the human step-up requirements only. An exemption
# waives a violation only when its decision is hitl_required; a block is never waived.
EXEMPTIBLE_RULES: frozenset[str] = frozenset(
    {R_HITL, R_OFF_HOURS_HITL, R_NEW_BENEFICIARY, R_CUMULATIVE_CAP}
)


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """What a rule is for, in terms a host application (and an auditor) can show."""

    id: str
    stage: int  # kill-chain stage 0 (containment) to 4
    severity: Literal["low", "medium", "high", "critical"]  # default; policy may re-label it
    decision: Literal["block", "hitl_required", "allow", "varies"]
    advisories: tuple[str, ...]
    summary: str
    rationale: str

    @property
    def name(self) -> str:
        return self.id.rsplit(".", 1)[-1]

    @property
    def overridable(self) -> bool:
        return self.id in OVERRIDABLE_RULES

    @property
    def exemptible(self) -> bool:
        return self.id in EXEMPTIBLE_RULES


_S1, _S2, _S3, _S4 = (f"CIAD-2026-0058 Stage {n}" for n in (1, 2, 3, 4))
_IDENTITY = "CIAD-2026-0049 identity"
_VELOCITY_CLAUSE = "CIAD-2026-0049 §3"
_CONTAIN = "CIAD-2026-0049 containment"

RULE_CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo(
        R_QUARANTINED,
        0,
        "critical",
        "block",
        (_CONTAIN,),
        "The agent run, or its token subject, is quarantined.",
        "After a containment-worthy detection every later call from the run (or subject) is "
        "refused, so an attacker cannot keep probing and cannot flood the audit log.",
    ),
    RuleInfo(
        R_TOKEN_INVALID,
        1,
        "critical",
        "block",
        (_IDENTITY,),
        "The agent token failed verification, or was revoked.",
        "Every decision keys on the agent run id, which is only trustworthy once a short-lived "
        "signed token has verified; an unauthenticated call never touches another run's state.",
    ),
    RuleInfo(
        R_ENV_PIVOT,
        1,
        "critical",
        "block",
        (_S1,),
        "A credential minted for one environment was used against another.",
        "Staging-to-production pivoting is the first step of the CRAFTY FALCON chain; a token is "
        "bound to one environment and any other use quarantines the run.",
    ),
    RuleInfo(
        R_MICRO_TX,
        2,
        "critical",
        "block",
        (_S2,),
        "Micro-value payments repeated inside a short window.",
        "Attackers verify unauthorised fund flows with tiny payments; the first is "
        "indistinguishable from a legitimate charge, so the breaker trips on the second.",
    ),
    RuleInfo(
        R_VELOCITY,
        2,
        "high",
        "block",
        (_VELOCITY_CLAUSE,),
        "Machine-speed bursts of calls, per tool and across all tools of a run.",
        "Enumeration and card-range scraping run far faster than a legitimate agent; counting "
        "across all tools stops an attacker spreading calls over many tools.",
    ),
    RuleInfo(
        R_STRUCTURING,
        2,
        "critical",
        "block",
        (_S2,),
        "Several payments that together exceed a threshold no single payment crosses.",
        "Splitting a large payout into sub-threshold payments evades a per-payment gate; totals "
        "are added up per run, per token subject and per payee across runs, and across "
        "currencies when aggregation is configured.",
    ),
    RuleInfo(
        R_SEQUENCE,
        2,
        "high",
        "block",
        (_S2,),
        "Reconnaissance calls followed by a payment within a window.",
        "Automated discovery immediately followed by a payout is the shape of the kill chain, "
        "not of ordinary use.",
    ),
    RuleInfo(
        R_CUMULATIVE_CAP,
        2,
        "high",
        "varies",
        (_S2,),
        "A rolling cap on what one run, and one subject, may move.",
        "Slow draining stays under every short window; a rolling cap needs step-up (or blocks) "
        "when a payment would take the total over it. Refused payments are not counted.",
    ),
    RuleInfo(
        R_TOOL_NOT_PINNED,
        3,
        "high",
        "block",
        (_S3,),
        "The tool is not in the token's pinned allowed_tools.",
        "Least privilege: a run may call only the tools its token names, so scope expansion "
        "toward settlement or transfer tools is refused and contained.",
    ),
    RuleInfo(
        R_HITL,
        3,
        "high",
        "hitl_required",
        (_S3,),
        "A high-value call on a protected tool needs human step-up.",
        "Settlement and disbursement above a per-currency threshold must not complete on an "
        "agent's say-so; the shield returns exactly what a human is asked to approve.",
    ),
    RuleInfo(
        R_NEW_BENEFICIARY,
        3,
        "high",
        "varies",
        (_S3,),
        "A high-value payment to a payee that is not known.",
        "Diverting funds to a mule account is caught at a lower threshold than the general "
        "gate; every payee of a bulk call is checked.",
    ),
    RuleInfo(
        R_APPROVAL_ACCEPTED,
        3,
        "low",
        "allow",
        (_S3,),
        "A signed per-transaction approval was accepted.",
        "Records who approved which exact transaction, so a step-up is evidence, not a flag.",
    ),
    RuleInfo(
        R_APPROVAL_REJECTED,
        3,
        "high",
        "hitl_required",
        (_S3,),
        "A presented approval was not honoured.",
        "An expired, forged, replayed or mismatched approval leaves step-up required and says "
        "why; it never falls back to the run-wide flag.",
    ),
    RuleInfo(
        R_LEGACY_STEP_UP,
        3,
        "low",
        "allow",
        (_S3,),
        "The deprecated run-wide hitl_step_up claim satisfied a step-up.",
        "The claim pre-authorises a whole run; each use is reported until it is switched off.",
    ),
    RuleInfo(
        R_EXEMPTION_APPLIED,
        3,
        "low",
        "allow",
        (_S3,),
        "A named, time-limited exemption waived a step-up requirement.",
        "Every waiver is attributable: the exemption id, approver, reason and expiry are logged.",
    ),
    RuleInfo(
        R_OFF_HOURS_HITL,
        4,
        "high",
        "hitl_required",
        (_S4,),
        "Protected tools need step-up in a low-monitoring window.",
        "Weekends, holidays and night hours are when passive supervision is weakest.",
    ),
    RuleInfo(
        R_OFF_HOURS,
        4,
        "low",
        "allow",
        (_S4,),
        "Off-hours thresholds were applied to this call.",
        "Informational: limits are tightened in low-monitoring windows.",
    ),
)
