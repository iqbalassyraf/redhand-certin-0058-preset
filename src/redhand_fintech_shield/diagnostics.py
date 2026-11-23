"""Configuration warnings: things that are legal but that an operator should look at.

``policy_warnings`` is pure (policy and a clock in, findings out) so it can be tested, printed by
``redhand-shield doctor`` and logged by the shield at startup. A warning is advice, never a
decision: the shield's behaviour does not change because of one.

Two things this preset cannot know and does not pretend to: movable and bank holidays (they differ
every year and by state), and live exchange rates. They are listed here as operator-supplied.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .models import PolicyConfig, SeverityLabel


@dataclass(frozen=True, slots=True)
class PolicyWarning:
    code: str
    message: str
    severity: SeverityLabel = "medium"

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code}: {self.message}"


def holiday_years_missing(policy: PolicyConfig, now: datetime) -> list[int]:
    """Years (this one and the next, in the policy's timezone) with no holiday entry."""
    off = policy.off_hours
    if not off.enabled:
        return []
    local_year = now.astimezone(ZoneInfo(off.timezone)).year
    present = {d.year for d in off.holidays}
    return [y for y in (local_year, local_year + 1) if y not in present]


def policy_warnings(policy: PolicyConfig, now: datetime) -> list[PolicyWarning]:
    """Everything worth an operator's attention in ``policy`` at time ``now``."""
    out: list[PolicyWarning] = []

    off = policy.off_hours
    if off.enabled and not off.holidays:
        out.append(
            PolicyWarning(
                "holidays-none",
                "off-hours tightening is on but no holidays are configured; movable festivals and "
                "bank holidays are operator-supplied",
                "high",
            )
        )
    elif off.enabled:
        for year in holiday_years_missing(policy, now):
            out.append(
                PolicyWarning(
                    "holidays-missing-year",
                    f"off_hours.holidays has no entries for {year}; add that year's fixed-date, "
                    "movable and bank holidays (they are operator-supplied)",
                    "high",
                )
            )

    for ex in policy.exemptions:
        if ex.expires_at <= now:
            out.append(
                PolicyWarning(
                    "exemption-expired",
                    f"exemption {ex.id!r} expired at {ex.expires_at.isoformat()} and is ignored",
                )
            )
        elif ex.expires_at - now <= timedelta(days=14):
            out.append(
                PolicyWarning(
                    "exemption-expiring",
                    f"exemption {ex.id!r} expires at {ex.expires_at.isoformat()}",
                    "low",
                )
            )

    for key in policy.token_keys:
        if key.retire_at is not None and key.retire_at <= now:
            out.append(
                PolicyWarning(
                    "key-retired", f"token key {key.kid!r} is retired and verifies nothing"
                )
            )
        elif key.retire_at is not None and key.retire_at - now <= timedelta(days=7):
            out.append(
                PolicyWarning(
                    "key-retiring",
                    f"token key {key.kid!r} retires at {key.retire_at.isoformat()}; make sure "
                    "the new key is signing",
                    "low",
                )
            )
    if policy.token_keys and all(
        k.retire_at is not None and k.retire_at <= now for k in policy.token_keys
    ):
        out.append(PolicyWarning("no-live-token-key", "every token key is retired", "critical"))

    if policy.audience is None and (policy.token_keys or policy.verifier_public_key_path):
        out.append(
            PolicyWarning(
                "no-audience",
                "no audience is configured, so tokens minted for another service verify here",
            )
        )
    if policy.approval.verifier_public_key_path is None:
        out.append(
            PolicyWarning(
                "no-approver-key",
                "approval.verifier_public_key_path is not set, so per-transaction approvals "
                "cannot be verified and step-up can only use the deprecated run-wide claim",
            )
        )
    if policy.approval.allow_legacy_step_up:
        out.append(
            PolicyWarning(
                "legacy-step-up",
                "the deprecated run-wide hitl_step_up claim is still honoured "
                "(approval.allow_legacy_step_up)",
                "low",
            )
        )
    if policy.mode.value == "observe_only":
        out.append(
            PolicyWarning("observe-only", "mode is observe_only: nothing is blocked", "high")
        )
    for rule_id, override in sorted(policy.rules.items()):
        if not override.enabled:
            out.append(PolicyWarning("rule-disabled", f"{rule_id} is switched off", "high"))
        elif override.mode.value == "observe_only":
            out.append(
                PolicyWarning(
                    "shadow-rule", f"{rule_id} runs in shadow: it reports but protects nothing"
                )
            )
    if not policy.cumulative_cap.enabled:
        out.append(
            PolicyWarning(
                "no-cumulative-cap", "no cumulative cap: slow draining is not limited", "low"
            )
        )
    if policy.aggregation.base_currency is None:
        out.append(
            PolicyWarning(
                "no-aggregation",
                "no cross-currency aggregation: splitting a payout across currencies is not "
                "added up (rates are operator-supplied)",
                "low",
            )
        )
    return out
