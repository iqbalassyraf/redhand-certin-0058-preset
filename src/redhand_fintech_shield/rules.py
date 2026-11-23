"""Stable rule identifiers and which of them policy may change.

Kept free of imports so both ``models`` (which validates policy against it) and ``detectors``
(which emits the rules) can use it without a cycle.
"""

from __future__ import annotations

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
