"""Embedding the shield in a host that authenticates agents itself (Phase 6 S0).

A host gateway verifies its own agent credential and passes the verified identity as claims.
These tests pin what that path trusts and what it still checks, that redacted findings carry no
call data, and that a non-Indian organization can replace the off-hours calendar safely.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from redhand_fintech_shield import (
    HashChainedAuditLog,
    HostVerifiedOnly,
    QuarantineRegistry,
    load_policy,
)
from redhand_fintech_shield.interceptor import Shield
from redhand_fintech_shield.models import (
    Decision,
    Env,
    Mode,
    PolicyConfig,
    TokenClaims,
    ToolCallContext,
)
from redhand_fintech_shield.rules import (
    R_ENV_PIVOT,
    R_OFF_HOURS_HITL,
    R_QUARANTINED,
    R_STRUCTURING,
    R_TOKEN_INVALID,
    R_TOOL_NOT_PINNED,
    RULE_CATALOG,
)

from .conftest import FakeClock

ROOT = Path(__file__).resolve().parents[1]
# What a host puts in ctx.token: a non-secret reference, never the credential itself.
REFERENCE = "host-verified:agent-7"


def _claims(clock: FakeClock, **overrides: object) -> TokenClaims:
    now = int(clock.now().timestamp())
    fields: dict[str, object] = {
        "iss": "host-gateway",
        "sub": "org-1:agent-7",
        "agent_run_id": "agent-7",
        "env": Env.PROD,
        "allowed_tools": ("charge_card", "settle_merchant", "list_merchants"),
        "hitl_step_up": False,
        "iat": now,
        "exp": now + 600,
        "jti": "host-session-1",
    }
    fields.update(overrides)
    return TokenClaims.model_validate(fields)


def _ctx(
    tool: str = "charge_card", amount: str | None = None, run: str = "agent-7"
) -> ToolCallContext:
    return ToolCallContext(
        agent_run_id=run,
        tool_name=tool,
        target_env=Env.PROD,
        token=REFERENCE,
        amount=Decimal(amount) if amount is not None else None,
        currency="USD" if amount is not None else None,
    )


def _rules(evaluation: object) -> set[str]:
    return {f.rule_id for f in evaluation.findings}  # type: ignore[attr-defined]


def test_verified_claims_allow_a_clean_call(shield: Shield, clock: FakeClock) -> None:
    ev = shield.evaluate_verified(_ctx(amount="25"), _claims(clock))
    assert ev.decision is Decision.ALLOW
    assert R_TOKEN_INVALID not in _rules(ev)


def test_the_reference_in_ctx_token_is_never_verified(shield: Shield, clock: FakeClock) -> None:
    # The same context through the normal path fails: the reference is not a token.
    assert R_TOKEN_INVALID in _rules(shield.evaluate(_ctx(amount="25")))
    assert shield.evaluate_verified(_ctx(amount="25"), _claims(clock)).decision is Decision.ALLOW


def test_expired_claims_are_refused_and_touch_no_state(shield: Shield, clock: FakeClock) -> None:
    claims = _claims(clock, exp=int(clock.now().timestamp()))
    ev = shield.evaluate_verified(_ctx(amount="25"), claims)
    assert ev.decision is Decision.BLOCK and R_TOKEN_INVALID in _rules(ev)
    assert any("expired" in f.detail for f in ev.findings)
    assert shield.quarantine.reason("agent-7") is None


def test_claims_for_another_run_are_refused(shield: Shield, clock: FakeClock) -> None:
    ev = shield.evaluate_verified(_ctx(amount="25", run="agent-8"), _claims(clock))
    assert ev.decision is Decision.BLOCK and R_TOKEN_INVALID in _rules(ev)


def test_environment_and_tool_pins_are_still_judged(shield: Shield, clock: FakeClock) -> None:
    pivot = shield.evaluate_verified(_ctx(amount="25"), _claims(clock, env=Env.STAGING))
    assert pivot.decision is Decision.BLOCK and R_ENV_PIVOT in _rules(pivot)
    unpinned = shield.evaluate_verified(
        _ctx("bulk_payout", "25", run="agent-9"), _claims(clock, agent_run_id="agent-9")
    )
    assert unpinned.decision is Decision.BLOCK and R_TOOL_NOT_PINNED in _rules(unpinned)


def test_revocation_applies_to_host_verified_claims(shield: Shield, clock: FakeClock) -> None:
    shield.revocations.revoke("subject", "org-1:agent-7", "operator froze the agent")
    ev = shield.evaluate_verified(_ctx(amount="25"), _claims(clock))
    assert ev.decision is Decision.BLOCK and R_TOKEN_INVALID in _rules(ev)


def test_detectors_and_quarantine_work_on_the_verified_path(
    shield: Shield, clock: FakeClock
) -> None:
    claims = _claims(clock)
    first = shield.evaluate_verified(_ctx("settle_merchant", "6000"), claims)
    assert first.decision is Decision.ALLOW
    clock.advance(10)
    second = shield.evaluate_verified(_ctx("settle_merchant", "6000"), claims)
    assert second.decision is Decision.BLOCK and R_STRUCTURING in _rules(second)
    clock.advance(1)
    after = shield.evaluate_verified(_ctx(amount="1"), claims)
    assert after.decision is Decision.BLOCK and R_QUARANTINED in _rules(after)


def test_observe_mode_never_blocks_on_the_verified_path(
    make_shield: Callable[..., Shield], clock: FakeClock
) -> None:
    observe = make_shield(Mode.OBSERVE_ONLY)
    ev = observe.evaluate_verified(_ctx(amount="25"), _claims(clock, env=Env.STAGING))
    assert R_ENV_PIVOT in _rules(ev)
    assert all(not f.enforced for f in ev.findings)


def test_audit_keeps_only_a_hash_of_the_reference(shield: Shield, clock: FakeClock) -> None:
    ev = shield.evaluate_verified(_ctx(amount="25"), _claims(clock))
    record = shield._write_audit(_ctx(amount="25"), ev, "executed")
    assert record is not None
    assert REFERENCE not in record.model_dump_json()


# --- Redaction -------------------------------------------------------------------------------


def test_redacted_finding_carries_no_call_data(shield: Shield, clock: FakeClock) -> None:
    claims = _claims(clock)
    shield.evaluate_verified(_ctx("settle_merchant", "6000"), claims)
    clock.advance(10)
    ev = shield.evaluate_verified(_ctx("settle_merchant", "7123.45"), claims)
    finding = next(f for f in ev.findings if f.rule_id == R_STRUCTURING)
    assert "7123.45" in finding.detail or "13123.45" in finding.detail  # the raw detail has values
    red = finding.redacted()
    summary = next(r.summary for r in RULE_CATALOG if r.id == R_STRUCTURING)
    assert red.detail == summary
    assert not any(ch.isdigit() for ch in red.detail.replace("CIAD-2026-0058", ""))
    assert "org-1" not in red.detail and "agent-7" not in red.detail
    assert red.model_dump(exclude={"detail"}) == finding.model_dump(exclude={"detail"})


def test_every_catalog_summary_is_free_of_call_data() -> None:
    for rule in RULE_CATALOG:
        assert rule.summary and "{" not in rule.summary
        assert not any(ch.isdigit() for ch in rule.summary), rule.id


def test_unknown_rule_redacts_to_a_generic_sentence(shield: Shield, clock: FakeClock) -> None:
    ev = shield.evaluate_verified(_ctx(amount="25"), _claims(clock, env=Env.STAGING))
    odd = ev.findings[0].model_copy(update={"rule_id": "host.unknown_rule", "detail": "payee 123"})
    assert odd.redacted().detail == "A policy rule fired."


# --- An organization outside India -----------------------------------------------------------


def test_southeast_asia_overlay_replaces_the_calendar_and_records_it() -> None:
    policy = load_policy(ROOT / "examples" / "southeast_asia_overlay.yaml")
    assert policy.off_hours.timezone == "Asia/Kuala_Lumpur"
    assert policy.off_hours.holidays == frozenset()
    loosened = " ".join(policy.provenance.loosened)  # type: ignore[union-attr]
    assert "off_hours.timezone" in loosened and "off_hours.holidays" in loosened
    assert R_OFF_HOURS_HITL in loosened


def test_southeast_asia_overlay_reports_but_does_not_block_off_hours(
    clock: FakeClock, tmp_path: Path
) -> None:
    policy = load_policy(ROOT / "examples" / "southeast_asia_overlay.yaml")
    # 20:00 in Kuala Lumpur on a Wednesday (12:00 UTC): outside business hours.
    clock.wall = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
    shield = Shield(
        policy,
        HostVerifiedOnly(),
        audit=HashChainedAuditLog(tmp_path / "audit.jsonl"),
        quarantine=QuarantineRegistry(),
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    ev = shield.evaluate_verified(_ctx("settle_merchant", "500"), _claims(clock))
    assert R_OFF_HOURS_HITL in _rules(ev)
    assert ev.decision is Decision.ALLOW
    assert next(f for f in ev.findings if f.rule_id == R_OFF_HOURS_HITL).enforced is False


def test_the_base_still_refuses_switching_off_hours_off(tmp_path: Path) -> None:
    overlay = tmp_path / "off.yaml"
    overlay.write_text(
        "extends: certin_ciad_2026_0058\n"
        'loosen: ["off_hours.enabled"]\n'
        "off_hours: {enabled: false}\n",
        "utf-8",
    )
    with pytest.raises(Exception, match="locked by the base policy"):
        load_policy(overlay)


def test_host_verified_only_refuses_every_token_on_the_normal_path(
    policy: PolicyConfig, clock: FakeClock
) -> None:
    shield = Shield(policy, HostVerifiedOnly(), clock=clock.now, monotonic=clock.monotonic)
    ev = shield.evaluate(_ctx(amount="25"))
    assert ev.decision is Decision.BLOCK and R_TOKEN_INVALID in _rules(ev)
    assert shield.evaluate_verified(_ctx(amount="25"), _claims(clock)).decision is Decision.ALLOW


def test_verifiers_satisfy_the_protocol(verifier: object) -> None:
    from redhand_fintech_shield import TokenVerifier

    assert isinstance(HostVerifiedOnly(), TokenVerifier)
    assert isinstance(verifier, TokenVerifier)
