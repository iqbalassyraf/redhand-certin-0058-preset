"""Phase 3 Milestone 3 tests: per-transaction step-up approvals.

Rationale: the run-wide ``hitl_step_up`` claim pre-authorises everything a run does. An approval
must authorise exactly one transaction: bound to its run, tool, environment, amount, currency,
payees and arguments; signed by a key the agent-token issuer does not hold; short lived; spendable
once. Every test below is a way an attacker (or a bug) could try to stretch an approval beyond
that, plus the happy path that proves legitimate approvals work.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from redhand_fintech_shield import (
    AgentTokenIssuer,
    Decision,
    Env,
    HITLRequiredError,
    Mode,
    PolicyConfig,
    PolicyLoadError,
    Shield,
    ToolCallContext,
)
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.approvals import (
    APPROVAL_TYP,
    ApprovalIssuer,
    ApprovalVerifier,
    NonceRegistry,
    arguments_digest,
    binding_mismatch,
    payees_of,
)
from redhand_fintech_shield.context import extract_tool_call_context, sanitize_arguments
from redhand_fintech_shield.crypto import private_key_to_pem, public_key_to_pem
from redhand_fintech_shield.detectors import (
    R_APPROVAL_ACCEPTED,
    R_APPROVAL_REJECTED,
    R_HITL,
    R_LEGACY_STEP_UP,
    R_NEW_BENEFICIARY,
)
from redhand_fintech_shield.gateway import MCPGateway
from redhand_fintech_shield.models import ApprovalPolicy, ApprovalRequest
from redhand_fintech_shield.protocols import NonceStore
from tests.conftest import PRESET, FakeClock

TOOL = "settle_merchant"


# --------------------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------------------


@pytest.fixture
def approver_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    return AgentTokenIssuer.generate_keypair()


@pytest.fixture
def approver(approver_keys: tuple[Ed25519PrivateKey, Ed25519PublicKey]) -> ApprovalIssuer:
    return ApprovalIssuer(approver_keys[0])


@pytest.fixture
def approval_verifier(
    approver_keys: tuple[Ed25519PrivateKey, Ed25519PublicKey], clock: FakeClock
) -> ApprovalVerifier:
    return ApprovalVerifier(approver_keys[1], clock=clock.now)


@pytest.fixture
def make_ashield(
    policy: PolicyConfig,
    verifier: Any,
    approval_verifier: ApprovalVerifier,
    clock: FakeClock,
) -> Callable[..., Shield]:
    def _make(
        *, legacy: bool = False, mode: Mode = Mode.ENFORCE, with_verifier: bool = True, **kw: Any
    ) -> Shield:
        pol = policy.model_copy(
            update={
                "mode": mode,
                "approval": policy.approval.model_copy(update={"allow_legacy_step_up": legacy}),
                **kw.pop("policy_updates", {}),
            }
        )
        return Shield(
            pol,
            verifier,
            approval_verifier=approval_verifier if with_verifier else None,
            clock=clock.now,
            monotonic=clock.monotonic,
            **kw,
        )

    return _make


@pytest.fixture
def token(issuer: AgentTokenIssuer, clock: FakeClock) -> str:
    return issuer.mint(
        subject="svc",
        agent_run_id="run-a",
        env=Env.PROD,
        allowed_tools=(TOOL, "charge_card", "bulk_payout"),
        now=clock.now(),
    )


def _paid(**kw: Any) -> str:
    return "paid"


def call(
    shield: Shield,
    token: str,
    *,
    amount: str = "15000",
    beneficiary: str = "acct-1",
    approval: str | None = None,
    run: str = "run-a",
    tool: str = TOOL,
    **extra: Any,
) -> ToolCallContext:
    args: dict[str, Any] = {
        "amount": amount,
        "currency": "USD",
        "beneficiary": beneficiary,
        "token": token,
        "agent_run_id": run,
        **extra,
    }
    if approval is not None:
        args["approval"] = approval
    return extract_tool_call_context(tool, args, bindings=shield.policy.tool_bindings)


def request_for(shield: Shield, token: str, **kw: Any) -> ApprovalRequest:
    """Ask the shield what it needs approved, exactly as a host application would."""
    evaluation = shield.evaluate(call(shield, token, **kw))
    assert evaluation.decision is Decision.HITL_REQUIRED
    assert evaluation.approval_request is not None
    return evaluation.approval_request


# --------------------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------------------


def test_arguments_digest_is_canonical_and_sensitive() -> None:
    a = arguments_digest({"amount": "1", "note": "x", "nested": {"b": 1, "a": 2}})
    b = arguments_digest({"nested": {"a": 2, "b": 1}, "note": "x", "amount": "1"})
    assert a == b and a is not None and len(a) == 64
    assert arguments_digest({"amount": "1", "note": "y"}) != arguments_digest(
        {"amount": "1", "note": "x"}
    )


def test_arguments_digest_returns_none_when_not_encodable() -> None:
    loop: dict[str, Any] = {}
    loop["self"] = loop
    assert arguments_digest(loop) is None


def test_payees_are_sorted_and_deduplicated() -> None:
    ctx = ToolCallContext(
        agent_run_id="r",
        tool_name="t",
        target_env=Env.PROD,
        token="x",
        beneficiary="b",
        beneficiaries=("c", "a", "b"),
    )
    assert payees_of(ctx) == ("a", "b", "c")


def test_issuer_refuses_bad_inputs(approver: ApprovalIssuer, shield: Shield, token: str) -> None:
    request = request_for(shield, token)
    with pytest.raises(ValueError, match="ttl_seconds"):
        approver.grant(request, approver="alice", ttl_seconds=0)
    with pytest.raises(ValueError, match="approver"):
        approver.grant(request, approver="  ")


def test_verifier_accepts_a_fresh_approval_and_exposes_claims(
    approver: ApprovalIssuer,
    approval_verifier: ApprovalVerifier,
    shield: Shield,
    token: str,
    clock: FakeClock,
) -> None:
    request = request_for(shield, token)
    grant = approver.grant(request, approver="alice", now=clock.now())
    claims = approval_verifier.verify(grant)
    assert claims.sub == "alice"
    assert claims.request_id == request.request_id
    assert claims.amount == "15000"
    assert claims.beneficiaries == ("acct-1",)
    assert len(approval_verifier.key_fingerprint) == 64


def test_verifier_rejects_everything_that_is_not_a_fresh_signed_approval(
    approver: ApprovalIssuer,
    approver_keys: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    approval_verifier: ApprovalVerifier,
    shield: Shield,
    token: str,
    clock: FakeClock,
) -> None:
    request = request_for(shield, token)
    good = approver.grant(request, approver="alice", ttl_seconds=60, now=clock.now())

    # garbage and tampering
    with pytest.raises(ValueError, match="rejected"):
        approval_verifier.verify("not-a-jws")
    head, body, sig = good.split(".")
    with pytest.raises(ValueError, match="rejected"):
        approval_verifier.verify(f"{head}.{body[:-2]}AA.{sig}")

    # signed by someone else
    attacker = ApprovalIssuer(Ed25519PrivateKey.generate())
    with pytest.raises(ValueError, match="rejected"):
        approval_verifier.verify(attacker.grant(request, approver="eve", now=clock.now()))

    # a token-shaped JWS (no approval typ) signed by the right key is still not an approval
    payload = {"iss": "redhand-approver", "sub": "x", "iat": 1, "exp": 2}
    with pytest.raises(ValueError, match="wrong typ"):
        approval_verifier.verify(jwt.encode(payload, approver_keys[0], algorithm="EdDSA"))

    # alg=none
    forged = jwt.encode(
        {"sub": "x"},
        None,  # type: ignore[arg-type]
        algorithm="none",
        headers={"typ": APPROVAL_TYP},
    )
    with pytest.raises(ValueError, match="rejected"):
        approval_verifier.verify(forged)

    # missing required claims
    bare = jwt.encode({"iss": "redhand-approver"}, approver_keys[0], "EdDSA", {"typ": APPROVAL_TYP})
    with pytest.raises(ValueError, match="rejected"):
        approval_verifier.verify(bare)

    # expiry, future issue time, over-long lifetime
    clock.advance(61)
    with pytest.raises(ValueError, match="expired"):
        approval_verifier.verify(good)
    clock.advance(-61)
    future = approver.grant(request, approver="a", now=clock.now() + timedelta(seconds=60))
    with pytest.raises(ValueError, match="future"):
        approval_verifier.verify(future)
    long_lived = approver.grant(request, approver="a", ttl_seconds=301, now=clock.now())
    with pytest.raises(ValueError, match="lifetime"):
        approval_verifier.verify(long_lived)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"agent_run_id": "run-z"}, "different agent run"),
        ({"tool_name": "bulk_payout"}, "different tool"),
        ({"target_env": Env.STAGING}, "different environment"),
        ({"currency": "INR"}, "different currency"),
        ({"amount": Decimal("14999")}, "different amount"),
        ({"amount": None}, "different amount"),
        ({"beneficiaries": ("acct-1", "acct-2")}, "different beneficiaries"),
        ({"beneficiaries": (), "beneficiary": None}, "different beneficiaries"),
        ({"arguments_digest": "0" * 64}, "different arguments"),
    ],
)
def test_every_binding_is_enforced(
    change: dict[str, Any],
    message: str,
    approver: ApprovalIssuer,
    approval_verifier: ApprovalVerifier,
    shield: Shield,
    token: str,
    clock: FakeClock,
) -> None:
    request = request_for(shield, token)
    claims = approval_verifier.verify(approver.grant(request, approver="a", now=clock.now()))
    ctx = call(shield, token)
    assert binding_mismatch(claims, ctx) is None
    assert message in (binding_mismatch(claims, ctx.model_copy(update=change)) or "")


def test_binding_mismatch_reports_an_unreadable_amount(
    approver: ApprovalIssuer,
    approval_verifier: ApprovalVerifier,
    shield: Shield,
    token: str,
    clock: FakeClock,
) -> None:
    request = request_for(shield, token)
    claims = approval_verifier.verify(approver.grant(request, approver="a", now=clock.now()))
    broken = claims.model_copy(update={"amount": "twelve"})
    assert "unreadable amount" in (binding_mismatch(broken, call(shield, token)) or "")


# --------------------------------------------------------------------------------------
# Nonce registry
# --------------------------------------------------------------------------------------


def test_nonce_is_single_use_until_it_expires(clock: FakeClock) -> None:
    reg = NonceRegistry(clock=clock.now)
    exp = int(clock.now().timestamp()) + 60
    assert reg.consume("n1", exp) is True
    assert reg.consume("n1", exp) is False
    assert isinstance(reg, NonceStore)
    clock.advance(61)
    assert reg.consume("n1", exp + 100) is True  # forgotten once past its expiry
    assert len(reg) == 1


def test_nonce_registry_fails_closed_when_full_of_live_nonces(clock: FakeClock) -> None:
    reg = NonceRegistry(max_entries=2, clock=clock.now)
    exp = int(clock.now().timestamp()) + 60
    assert reg.consume("a", exp) and reg.consume("b", exp)
    assert reg.consume("c", exp) is False  # would have to forget a live nonce
    clock.advance(61)
    assert reg.consume("c", exp + 200) is True  # expired ones are purged to make room


def test_nonce_journal_survives_restart_and_tolerates_damage(
    tmp_path: Path, clock: FakeClock
) -> None:
    journal = tmp_path / "nonces.jsonl"
    exp = int(clock.now().timestamp()) + 60
    assert NonceRegistry(journal, clock=clock.now).consume("spent", exp)
    with journal.open("a", encoding="utf-8") as fh:
        fh.write("\n")  # blank line
        fh.write('{"nonce": "old", "exp": 1}\n')  # already expired
        fh.write("{torn line\n")  # crash mid-write
    restarted = NonceRegistry(journal, clock=clock.now)
    assert restarted.consume("spent", exp) is False
    assert len(restarted) == 1
    assert NonceRegistry(tmp_path / "absent.jsonl", clock=clock.now).consume("x", exp)


# --------------------------------------------------------------------------------------
# Shield: the happy path and the request a host application renders
# --------------------------------------------------------------------------------------


def test_unapproved_high_value_call_yields_a_complete_approval_request(
    make_ashield: Callable[..., Shield], token: str
) -> None:
    shield = make_ashield()
    ctx = call(shield, token, extra_note="rent")
    evaluation = shield.evaluate(ctx)
    request = evaluation.approval_request
    assert evaluation.decision is Decision.HITL_REQUIRED and request is not None
    assert (request.agent_run_id, request.tool_name, request.target_env) == (
        "run-a",
        TOOL,
        Env.PROD,
    )
    assert (request.amount, request.currency) == (Decimal("15000"), "USD")
    assert request.beneficiaries == ("acct-1",)
    assert request.arguments_digest == ctx.arguments_digest
    assert set(request.reasons) == {R_HITL, R_NEW_BENEFICIARY}
    assert len(request.details) == 2


def test_valid_approval_authorises_exactly_that_call_once(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    request = request_for(shield, token)
    grant = approver.grant(request, approver="alice@bank", now=clock.now())

    ok = shield.evaluate(call(shield, token, approval=grant))
    assert ok.decision is Decision.ALLOW
    assert ok.approval_request is None
    accepted = [f for f in ok.findings if f.rule_id == R_APPROVAL_ACCEPTED]
    assert accepted and "alice@bank" in accepted[0].detail
    assert accepted[0].decision is Decision.ALLOW

    replay = shield.evaluate(call(shield, token, approval=grant))
    assert replay.decision is Decision.HITL_REQUIRED
    rejected = [f for f in replay.findings if f.rule_id == R_APPROVAL_REJECTED]
    assert rejected and "already used" in rejected[0].detail
    assert replay.approval_request is not None  # a fresh request, ready for a new approval


def test_approval_survives_the_agents_retry_with_reordered_arguments(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    first = call(shield, token, memo="x", ref="1")
    request = shield.evaluate(first).approval_request
    assert request is not None
    grant = approver.grant(request, approver="alice", now=clock.now())
    retry = call(shield, token, ref="1", memo="x", approval=grant)  # keys in another order
    assert shield.evaluate(retry).decision is Decision.ALLOW


# --------------------------------------------------------------------------------------
# Shield: every attempt to stretch an approval
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("call_change", "message"),
    [
        ({"amount": "15001"}, "different amount"),
        ({"beneficiary": "acct-evil"}, "different beneficiaries"),
        ({"tool": "bulk_payout"}, "different tool"),
        ({"memo": "changed"}, "different arguments"),
    ],
)
def test_approval_cannot_be_reused_for_a_different_transaction(
    call_change: dict[str, Any],
    message: str,
    make_ashield: Callable[..., Shield],
    approver: ApprovalIssuer,
    token: str,
    clock: FakeClock,
) -> None:
    shield = make_ashield()
    original = shield.evaluate(call(shield, token, memo="orig")).approval_request
    assert original is not None
    grant = approver.grant(original, approver="alice", now=clock.now())

    altered = shield.evaluate(
        call(shield, token, approval=grant, **{"memo": "orig", **call_change})
    )
    assert altered.decision is not Decision.ALLOW
    assert any(
        f.rule_id == R_APPROVAL_REJECTED and message in f.detail for f in altered.findings
    ), [f.detail for f in altered.findings]

    # A rejected attempt must not burn the approval: the real transaction still goes through.
    genuine = shield.evaluate(call(shield, token, approval=grant, memo="orig"))
    assert genuine.decision is Decision.ALLOW


def test_approval_for_another_run_is_refused(
    make_ashield: Callable[..., Shield],
    approver: ApprovalIssuer,
    issuer: AgentTokenIssuer,
    token: str,
    clock: FakeClock,
) -> None:
    shield = make_ashield()
    request = request_for(shield, token)
    grant = approver.grant(request, approver="alice", now=clock.now())
    other_token = issuer.mint(
        subject="svc",
        agent_run_id="run-b",
        env=Env.PROD,
        allowed_tools=(TOOL,),
        now=clock.now(),
    )
    stolen = shield.evaluate(call(shield, other_token, run="run-b", approval=grant))
    assert stolen.decision is Decision.HITL_REQUIRED
    assert any("different agent run" in f.detail for f in stolen.findings)


def test_expired_forged_and_unconfigured_approvals_are_refused(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    request = request_for(shield, token)

    expired = approver.grant(request, approver="alice", ttl_seconds=30, now=clock.now())
    clock.advance(31)
    ev = shield.evaluate(call(shield, token, approval=expired))
    assert ev.decision is Decision.HITL_REQUIRED
    assert any("expired" in f.detail for f in ev.findings)

    forged = ApprovalIssuer(Ed25519PrivateKey.generate()).grant(
        request, approver="mallory", now=clock.now()
    )
    ev = shield.evaluate(call(shield, token, approval=forged))
    assert ev.decision is Decision.HITL_REQUIRED
    assert any(f.rule_id == R_APPROVAL_REJECTED for f in ev.findings)

    bare = make_ashield(with_verifier=False)
    ev = bare.evaluate(call(bare, token, approval=forged))
    assert ev.decision is Decision.HITL_REQUIRED
    assert any("no approval verifier" in f.detail for f in ev.findings)


def test_approval_can_never_clear_a_block(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    base = PolicyConfig.from_yaml(PRESET)
    nb = base.new_beneficiary.model_copy(update={"action": "block"})
    shield = make_ashield(policy_updates={"new_beneficiary": nb})
    ctx = call(shield, token)
    assert shield.evaluate(ctx).decision is Decision.BLOCK
    request = build_request_for(shield, ctx)
    grant = approver.grant(request, approver="alice", now=clock.now())
    again = shield.evaluate(call(shield, token, approval=grant, run="run-a"))
    assert again.decision is Decision.BLOCK


def build_request_for(shield: Shield, ctx: ToolCallContext) -> ApprovalRequest:
    from redhand_fintech_shield.approvals import build_request

    return build_request(ctx, (), (), shield._clock())


def test_approval_presented_when_none_is_needed_is_ignored_and_not_spent(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    small = call(shield, token, amount="500", beneficiary="acct-1")
    request = build_request_for(shield, small)
    grant = approver.grant(request, approver="alice", now=clock.now())
    ev = shield.evaluate(call(shield, token, amount="500", beneficiary="acct-1", approval=grant))
    assert ev.decision is Decision.ALLOW
    assert not any(f.rule_id == R_APPROVAL_ACCEPTED for f in ev.findings)
    assert len(shield._nonces) == 0  # type: ignore[arg-type]


def test_one_approval_covers_every_pending_requirement(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    request = request_for(shield, token)
    assert len(request.reasons) == 2  # HITL gate and new-beneficiary gate both fire
    grant = approver.grant(request, approver="alice", now=clock.now())
    ev = shield.evaluate(call(shield, token, approval=grant))
    assert ev.decision is Decision.ALLOW


def test_concurrent_use_of_one_approval_succeeds_exactly_once(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    request = request_for(shield, token)
    grant = approver.grant(request, approver="alice", now=clock.now())
    results: list[Decision] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        ctx = call(shield, token, approval=grant)
        barrier.wait()
        results.append(shield.evaluate(ctx).decision)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(Decision.ALLOW) == 1
    assert results.count(Decision.HITL_REQUIRED) == 7


def test_nonce_store_failures_fail_closed(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    class Broken:
        def consume(self, nonce: str, expires_at: int) -> bool:
            raise OSError("disk full")

    class Refusing:
        def consume(self, nonce: str, expires_at: int) -> bool:
            return False

    for store, expected in ((Broken(), "store unavailable"), (Refusing(), "already used")):
        shield = make_ashield(nonce_store=store)
        request = request_for(shield, token)
        grant = approver.grant(request, approver="alice", now=clock.now())
        ev = shield.evaluate(call(shield, token, approval=grant))
        assert ev.decision is Decision.HITL_REQUIRED
        assert any(expected in f.detail for f in ev.findings)


def test_observe_only_reports_the_same_findings_without_blocking(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    enforce, observe = make_ashield(), make_ashield(mode=Mode.OBSERVE_ONLY)
    request = request_for(enforce, token)
    grant = approver.grant(request, approver="alice", now=clock.now())
    for shield in (enforce, observe):
        ev = shield.evaluate(call(shield, token, approval=grant))
        assert ev.decision is Decision.ALLOW
        assert R_APPROVAL_ACCEPTED in {f.rule_id for f in ev.findings}


# --------------------------------------------------------------------------------------
# Legacy run-wide claim and key separation
# --------------------------------------------------------------------------------------


@pytest.fixture
def stepped_up_token(issuer: AgentTokenIssuer, clock: FakeClock) -> str:
    return issuer.mint(
        subject="svc",
        agent_run_id="run-a",
        env=Env.PROD,
        allowed_tools=(TOOL,),
        hitl_step_up=True,
        now=clock.now(),
    )


def test_legacy_claim_still_works_but_is_reported_as_deprecated(
    make_ashield: Callable[..., Shield], stepped_up_token: str
) -> None:
    shield = make_ashield(legacy=True)
    ev = shield.evaluate(call(shield, stepped_up_token))
    assert ev.decision is Decision.ALLOW
    legacy = [f for f in ev.findings if f.rule_id == R_LEGACY_STEP_UP]
    assert legacy and "deprecated" in legacy[0].detail
    assert legacy[0].decision is Decision.ALLOW


def test_legacy_claim_can_be_switched_off(
    make_ashield: Callable[..., Shield], stepped_up_token: str
) -> None:
    shield = make_ashield(legacy=False)
    ev = shield.evaluate(call(shield, stepped_up_token))
    assert ev.decision is Decision.HITL_REQUIRED
    assert ev.approval_request is not None


def test_rejected_approval_does_not_fall_back_to_the_legacy_claim(
    make_ashield: Callable[..., Shield], stepped_up_token: str, approver: ApprovalIssuer
) -> None:
    shield = make_ashield(legacy=True)
    forged = ApprovalIssuer(Ed25519PrivateKey.generate()).grant(
        shield.evaluate(call(shield, stepped_up_token)).approval_request
        or build_request_for(shield, call(shield, stepped_up_token)),
        approver="mallory",
    )
    ev = shield.evaluate(call(shield, stepped_up_token, approval=forged))
    assert ev.decision is Decision.HITL_REQUIRED
    assert not any(f.rule_id == R_LEGACY_STEP_UP for f in ev.findings)


def test_approver_key_must_differ_from_token_key(
    policy: PolicyConfig,
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    verifier: Any,
    clock: FakeClock,
) -> None:
    same = ApprovalVerifier(keypair[1], clock=clock.now)
    with pytest.raises(PolicyLoadError, match="must differ"):
        Shield(policy, verifier, approval_verifier=same, clock=clock.now)


def test_approval_verifier_is_loaded_from_the_policy_key_path(
    policy: PolicyConfig,
    verifier: Any,
    approver_keys: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    tmp_path: Path,
    clock: FakeClock,
) -> None:
    pem = tmp_path / "approver_pub.pem"
    pem.write_bytes(public_key_to_pem(approver_keys[1]))
    pol = policy.model_copy(
        update={
            "approval": policy.approval.model_copy(update={"verifier_public_key_path": pem}),
        }
    )
    shield = Shield(pol, verifier, clock=clock.now, monotonic=clock.monotonic)
    assert shield._approval_verifier is not None


def test_approval_policy_is_bounded() -> None:
    assert ApprovalPolicy().max_ttl_seconds == 300
    with pytest.raises(ValueError):
        ApprovalPolicy(max_ttl_seconds=0)
    with pytest.raises(ValueError):
        ApprovalPolicy(max_ttl_seconds=3601)
    assert PolicyConfig.from_yaml(PRESET).approval.issuer == "redhand-approver"


# --------------------------------------------------------------------------------------
# Audit, decorator, extraction
# --------------------------------------------------------------------------------------


def test_audit_log_stores_only_a_hash_of_the_approval(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    shield = make_ashield()
    request = request_for(shield, token)
    grant = approver.grant(request, approver="alice", now=clock.now())
    guarded = shield.guard(_paid, ctx_arg="ctx")
    assert guarded(ctx=call(shield, token, approval=grant)) == "paid"
    shield.close()
    text = Path(shield.policy.audit_path).read_text(encoding="utf-8")
    assert grant not in text and token not in text
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    ctx_logged = records[-1]["context"]
    assert ctx_logged["approval"].startswith("sha256:")
    assert any(f["rule_id"] == R_APPROVAL_ACCEPTED for f in records[-1]["findings"])


def test_decorator_raises_with_the_approval_request_attached(
    make_ashield: Callable[..., Shield], token: str
) -> None:
    shield = make_ashield()
    guarded = shield.guard(_paid, ctx_arg="ctx")
    with pytest.raises(HITLRequiredError) as err:
        guarded(ctx=call(shield, token))
    assert err.value.approval_request is not None
    assert err.value.approval_request.amount == Decimal("15000")


def test_extraction_finds_approval_in_every_transport_and_hides_it_from_the_tool() -> None:
    for where in ("meta", "arg_meta", "arguments", "_approval"):
        meta = {"approval": "A.B.C"} if where == "meta" else None
        args: dict[str, Any] = {"amount": "1", "currency": "USD", "token": "t"}
        if where == "arg_meta":
            args["_meta"] = {"approval": "A.B.C"}
        if where == "arguments":
            args["approval"] = "A.B.C"
        if where == "_approval":
            args["_approval"] = "A.B.C"
        ctx = extract_tool_call_context("charge_card", args, meta=meta)
        assert ctx.approval == "A.B.C", where
        assert "approval" not in ctx.metadata
    clean = sanitize_arguments({"amount": "1", "approval": "x", "_approval": "y", "token": "z"})
    assert clean == {"amount": "1"}


def test_digest_ignores_credentials_but_not_payload() -> None:
    base = {"amount": "1", "currency": "USD", "token": "t1", "approval": "a1"}
    one = extract_tool_call_context("charge_card", base)
    two = extract_tool_call_context("charge_card", {**base, "token": "t2", "approval": "a2"})
    three = extract_tool_call_context("charge_card", {**base, "amount": "2"})
    assert one.arguments_digest == two.arguments_digest
    assert one.arguments_digest != three.arguments_digest


# --------------------------------------------------------------------------------------
# Gateway end to end
# --------------------------------------------------------------------------------------


def test_gateway_round_trip_request_approve_execute_replay(
    make_ashield: Callable[..., Shield], approver: ApprovalIssuer, token: str, clock: FakeClock
) -> None:
    import asyncio

    seen: list[dict[str, Any]] = []

    class Executor:
        def execute(self, tool_name: str, arguments: dict[str, Any], context: Any = None) -> Any:
            seen.append(arguments)
            return "settled"

        async def aexecute(
            self, tool_name: str, arguments: dict[str, Any], context: Any = None
        ) -> Any:
            return self.execute(tool_name, arguments, context)

    shield = make_ashield()
    gateway = MCPGateway(shield=shield, executor=Executor(), default_env=Env.PROD)

    def rpc(meta_extra: dict[str, Any]) -> dict[str, Any]:
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": TOOL,
                "arguments": {"amount": "15000", "currency": "USD", "beneficiary": "acct-1"},
                "_meta": {"token": token, "agent_run_id": "run-a", **meta_extra},
            },
        }
        response = asyncio.run(gateway.handle_message(message))
        assert response is not None
        result: dict[str, Any] = response["result"]
        return result

    blocked = rpc({})
    assert blocked["isError"] is True
    request = ApprovalRequest.model_validate(blocked["_meta"]["approval_request"])

    grant = approver.grant(request, approver="alice", now=clock.now())
    done = rpc({"approval": grant})
    assert done["isError"] is False
    assert seen == [{"amount": "15000", "currency": "USD", "beneficiary": "acct-1"}]

    replay = rpc({"approval": grant})
    assert replay["isError"] is True
    assert any(f["rule_id"] == R_APPROVAL_REJECTED for f in replay["_meta"]["findings"])


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def test_cli_keygen_name_and_approve_produce_a_working_approval(
    tmp_path: Path,
    make_ashield: Callable[..., Shield],
    token: str,
    clock: FakeClock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["keygen", str(tmp_path), "--name", "approver"]) == 0
    assert "approval.verifier_public_key_path" in capsys.readouterr().out
    key_path = tmp_path / "approver_ed25519_private.pem"
    public = serialization.load_pem_public_key(
        (tmp_path / "approver_ed25519_public.pem").read_bytes()
    )
    assert isinstance(public, Ed25519PublicKey)

    shield = make_ashield()
    request = request_for(shield, token)
    request_file = tmp_path / "request.json"
    request_file.write_text(request.model_dump_json(), encoding="utf-8")

    assert (
        main(
            [
                "approve",
                str(request_file),
                "--key",
                str(key_path),
                "--approver",
                "alice",
                "--ttl",
                "60",
            ]
        )
        == 0
    )
    grant = capsys.readouterr().out.strip()
    claims = ApprovalVerifier(public).verify(grant)  # the CLI signs with the real clock
    assert claims.sub == "alice" and claims.request_id == request.request_id


def test_cli_approve_rejects_bad_inputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    request_file = tmp_path / "request.json"
    request_file.write_text("{not json", encoding="utf-8")
    key = tmp_path / "k.pem"
    key.write_bytes(private_key_to_pem(Ed25519PrivateKey.generate()))
    assert main(["approve", str(request_file), "--key", str(key), "--approver", "a"]) == 2
    assert "cannot read approval request" in capsys.readouterr().err

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = tmp_path / "rsa.pem"
    rsa_pem.write_bytes(
        rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    good = ApprovalRequest(
        request_id="r",
        agent_run_id="run",
        tool_name="t",
        target_env=Env.PROD,
        requested_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    request_file.write_text(good.model_dump_json(), encoding="utf-8")
    assert main(["approve", str(request_file), "--key", str(rsa_pem), "--approver", "a"]) == 2
    assert "not an Ed25519 private key" in capsys.readouterr().err
