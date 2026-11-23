"""Phase 3.5 D: token audience, key rotation (kid key ring) and revocation.

Rationale: run tokens are short lived but not instantly recallable, and the key that signs them
must be rotatable without an outage. A token is bound to the service it is for (aud), verified
against a ring of keys that retire on a schedule, and can be revoked by id, subject or run, with the
revocation reaching a running shield without a restart.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    ApprovalVerifier,
    Decision,
    Env,
    KeyRing,
    PolicyConfig,
    PolicyLoadError,
    RevocationRegistry,
    RevocationStore,
    Shield,
    TokenInvalidError,
    TokenKey,
    ToolCallContext,
)
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.crypto import public_key_to_pem
from redhand_fintech_shield.detectors import R_TOKEN_INVALID
from redhand_fintech_shield.models import TokenKeyConfig
from tests.conftest import FakeClock

Pair = tuple[Ed25519PrivateKey, Ed25519PublicKey]


def _paid(**kw: Any) -> str:
    return "paid"


def mint(issuer: AgentTokenIssuer, clock: FakeClock, **kw: Any) -> str:
    params: dict[str, Any] = {
        "subject": "svc",
        "agent_run_id": "run-1",
        "env": Env.PROD,
        "allowed_tools": ("charge_card",),
        "now": clock.now(),
    }
    params.update(kw)
    return issuer.mint(**params)


def ctx_for(token: str, run: str = "run-1") -> ToolCallContext:
    return ToolCallContext(
        agent_run_id=run,
        tool_name="charge_card",
        target_env=Env.PROD,
        token=token,
        amount=Decimal("100"),
        currency="USD",
    )


# --------------------------------------------------------------------------------------
# Audience
# --------------------------------------------------------------------------------------


def test_audience_must_match_when_configured(keypair: Pair, clock: FakeClock) -> None:
    issuer = AgentTokenIssuer(keypair[0])
    strict = AgentTokenVerifier(keypair[1], clock=clock.now, audience="payments-gateway")
    claims = strict.verify(mint(issuer, clock, audience="payments-gateway"))
    assert claims.aud == "payments-gateway"
    with pytest.raises(TokenInvalidError, match="InvalidAudienceError"):
        strict.verify(mint(issuer, clock, audience="some-other-service"))
    with pytest.raises(TokenInvalidError, match="MissingRequiredClaimError"):
        strict.verify(mint(issuer, clock))  # no aud at all


def test_a_token_with_an_audience_still_verifies_when_none_is_configured(
    keypair: Pair, clock: FakeClock
) -> None:
    issuer = AgentTokenIssuer(keypair[0])
    lenient = AgentTokenVerifier(keypair[1], clock=clock.now)
    assert lenient.verify(mint(issuer, clock, audience="anything")).aud == "anything"
    assert lenient.verify(mint(issuer, clock)).aud is None


def test_policy_audience_is_enforced_by_a_shield_built_from_the_policy(
    policy: PolicyConfig, keypair: Pair, clock: FakeClock, tmp_path: Path
) -> None:
    pem = tmp_path / "pub.pem"
    pem.write_bytes(public_key_to_pem(keypair[1]))
    pol = policy.model_copy(update={"verifier_public_key_path": pem, "audience": "gw"})
    sh = Shield(pol, clock=clock.now, monotonic=clock.monotonic)
    issuer = AgentTokenIssuer(keypair[0])
    assert sh.evaluate(ctx_for(mint(issuer, clock, audience="gw"))).decision is Decision.ALLOW
    wrong = sh.evaluate(ctx_for(mint(issuer, clock, audience="other"), "run-2"))
    assert wrong.decision is Decision.BLOCK
    assert wrong.findings[0].rule_id == R_TOKEN_INVALID


# --------------------------------------------------------------------------------------
# Key ring and rotation
# --------------------------------------------------------------------------------------


def two_keys() -> tuple[Pair, Pair]:
    return AgentTokenIssuer.generate_keypair(), AgentTokenIssuer.generate_keypair()


def test_key_ring_validates_its_input() -> None:
    key = AgentTokenIssuer.generate_keypair()[1]
    with pytest.raises(ValueError, match="at least one key"):
        KeyRing([])
    with pytest.raises(ValueError, match="duplicate kid"):
        KeyRing([TokenKey("a", key), TokenKey("a", key)])
    ring = KeyRing([TokenKey("a", key)])
    assert len(ring) == 1 and ring.get("a") is not None and ring.get("b") is None


def test_rotation_old_and_new_keys_verify_during_the_overlap_then_the_old_one_retires(
    clock: FakeClock,
) -> None:
    old, new = two_keys()
    retire = clock.now() + timedelta(minutes=30)
    ring = KeyRing([TokenKey("2026-a", old[1], retire_at=retire), TokenKey("2026-b", new[1])])
    verifier = AgentTokenVerifier(ring, clock=clock.now)
    old_issuer = AgentTokenIssuer(old[0], kid="2026-a")
    new_issuer = AgentTokenIssuer(new[0], kid="2026-b")

    old_token, new_token = mint(old_issuer, clock), mint(new_issuer, clock)
    assert verifier.verify(old_token).sub == verifier.verify(new_token).sub == "svc"
    clock.advance(30 * 60)  # the old key reaches retire_at
    with pytest.raises(TokenInvalidError, match="retired"):
        verifier.verify(old_token)
    assert verifier.verify(mint(new_issuer, clock)).sub == "svc"


def test_ring_refuses_unknown_missing_and_swapped_key_ids(clock: FakeClock) -> None:
    old, new = two_keys()
    verifier = AgentTokenVerifier(
        KeyRing([TokenKey("a", old[1]), TokenKey("b", new[1])]), clock=clock.now
    )
    with pytest.raises(TokenInvalidError, match="unknown key id"):
        verifier.verify(mint(AgentTokenIssuer(old[0], kid="zzz"), clock))
    with pytest.raises(TokenInvalidError, match="no key id"):
        verifier.verify(mint(AgentTokenIssuer(old[0]), clock))
    # signed by key a but claiming to be key b: the kid only selects a key, it never trusts one
    with pytest.raises(TokenInvalidError, match="InvalidSignatureError"):
        verifier.verify(mint(AgentTokenIssuer(old[0], kid="b"), clock))
    with pytest.raises(TokenInvalidError, match="DecodeError"):
        verifier.verify("not-a-token")


def test_single_key_mode_is_unchanged_and_ignores_kid(keypair: Pair, clock: FakeClock) -> None:
    verifier = AgentTokenVerifier(keypair[1], clock=clock.now)
    assert verifier.verify(mint(AgentTokenIssuer(keypair[0], kid="anything"), clock)).sub == "svc"
    assert verifier.verify(mint(AgentTokenIssuer(keypair[0]), clock)).sub == "svc"
    assert len(verifier.key_fingerprint) == 64 and len(verifier.key_fingerprints) == 1


def test_a_ring_exposes_every_fingerprint_but_no_single_one() -> None:
    old, new = two_keys()
    verifier = AgentTokenVerifier(KeyRing([TokenKey("a", old[1]), TokenKey("b", new[1])]))
    assert len(verifier.key_fingerprints) == 2
    with pytest.raises(AttributeError, match="several keys"):
        _ = verifier.key_fingerprint


def write_keys(tmp_path: Path, *pairs: Pair) -> list[Path]:
    paths = []
    for index, pair in enumerate(pairs):
        path = tmp_path / f"k{index}.pem"
        path.write_bytes(public_key_to_pem(pair[1]))
        paths.append(path)
    return paths


def test_policy_key_ring_drives_a_shield_through_a_rotation(
    policy: PolicyConfig, tmp_path: Path, clock: FakeClock
) -> None:
    old, new = two_keys()
    old_pem, new_pem = write_keys(tmp_path, old, new)
    pol = policy.model_copy(
        update={
            "token_keys": (
                TokenKeyConfig(
                    kid="a", public_key_path=old_pem, retire_at=clock.now() + timedelta(hours=1)
                ),
                TokenKeyConfig(kid="b", public_key_path=new_pem),
            )
        }
    )
    sh = Shield(pol, clock=clock.now, monotonic=clock.monotonic)
    old_issuer, new_issuer = AgentTokenIssuer(old[0], kid="a"), AgentTokenIssuer(new[0], kid="b")
    assert sh.evaluate(ctx_for(mint(old_issuer, clock), "run-1")).decision is Decision.ALLOW
    assert sh.evaluate(ctx_for(mint(new_issuer, clock, agent_run_id="r2"), "r2")).decision is (
        Decision.ALLOW
    )
    clock.advance(3600)
    retired = sh.evaluate(ctx_for(mint(old_issuer, clock, agent_run_id="r3"), "r3"))
    assert retired.decision is Decision.BLOCK and "retired" in retired.findings[0].detail


def test_policy_token_key_validation() -> None:
    cfg = {"kid": "a", "public_key_path": "a.pem"}
    with pytest.raises(ValidationError, match="either token_keys or verifier_public_key_path"):
        PolicyConfig.model_validate({"token_keys": [cfg], "verifier_public_key_path": "k.pem"})
    with pytest.raises(ValidationError, match="duplicate kid"):
        PolicyConfig.model_validate({"token_keys": [cfg, cfg]})
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"token_keys": [{**cfg, "retire_at": "2026-01-01T00:00:00"}]})


def test_the_approver_key_may_not_equal_any_key_in_the_ring(
    policy: PolicyConfig, tmp_path: Path, clock: FakeClock
) -> None:
    first, second = two_keys()
    pems = write_keys(tmp_path, first, second)
    pol = policy.model_copy(
        update={
            "token_keys": (
                TokenKeyConfig(kid="a", public_key_path=pems[0]),
                TokenKeyConfig(kid="b", public_key_path=pems[1]),
            )
        }
    )
    with pytest.raises(PolicyLoadError, match="must differ"):
        Shield(pol, approval_verifier=ApprovalVerifier(second[1], clock=clock.now), clock=clock.now)
    approver = AgentTokenIssuer.generate_keypair()[1]
    Shield(pol, approval_verifier=ApprovalVerifier(approver, clock=clock.now), clock=clock.now)


def test_key_ring_changes_are_loosening_in_an_overlay_and_ignore_file_paths(
    tmp_path: Path,
) -> None:
    from redhand_fintech_shield import load_policy

    overlay = tmp_path / "o.yaml"
    overlay.write_text(
        "extends: certin_ciad_2026_0058\ntoken_keys:\n  - {kid: a, public_key_path: k.pem}\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyLoadError, match="token_keys"):
        load_policy(overlay)
    overlay.write_text(
        "extends: certin_ciad_2026_0058\nloosen: [token_keys]\n"
        "token_keys:\n  - {kid: a, public_key_path: k.pem}\n",
        encoding="utf-8",
    )
    ring = load_policy(overlay)
    moved = ring.model_copy(
        update={"token_keys": (TokenKeyConfig(kid="a", public_key_path=Path("/else/k.pem")),)}
    )
    renamed = ring.model_copy(
        update={"token_keys": (TokenKeyConfig(kid="b", public_key_path=Path("k.pem")),)}
    )
    assert ring.fingerprint() == moved.fingerprint() != renamed.fingerprint()


def test_keygen_kid_prints_the_policy_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["keygen", str(tmp_path), "--kid", "2026-q4"]) == 0
    out = capsys.readouterr().out
    assert "kid: 2026-q4" in out and "public_key_path:" in out and "token_keys:" in out


# --------------------------------------------------------------------------------------
# Revocation
# --------------------------------------------------------------------------------------


def test_registry_revokes_by_jti_subject_and_run(clock: FakeClock) -> None:
    reg = RevocationRegistry(clock=clock.now)
    assert isinstance(reg, RevocationStore)
    assert reg.reason("j1", "s1", "r1") is None
    assert reg.revoke("jti", "j1", "leaked") is True
    assert reg.revoke("jti", "j1", "leaked again") is False
    assert "jti 'j1' revoked: leaked" in (reg.reason("j1", "s9", "r9") or "")
    assert reg.revoke("subject", "s2", "compromised host")
    assert "subject 's2'" in (reg.reason("jX", "s2", "r9") or "")
    assert reg.revoke("run", "r3", "operator stop")
    assert "run 'r3'" in (reg.reason("jX", "sX", "r3") or "")
    assert reg.reason("other", "other", "other") is None


def test_registry_rejects_bad_input(clock: FakeClock) -> None:
    reg = RevocationRegistry(clock=clock.now)
    with pytest.raises(ValueError, match="kind must be"):
        reg.revoke("token", "x", "why")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="needs a value and a reason"):
        reg.revoke("jti", " ", "why")
    with pytest.raises(ValueError, match="needs a value and a reason"):
        reg.revoke("jti", "x", "")


def test_a_revocation_expires_with_the_token(clock: FakeClock) -> None:
    reg = RevocationRegistry(clock=clock.now)
    reg.revoke("jti", "j1", "leaked", expires_at=int(clock.now().timestamp()) + 60)
    assert reg.reason("j1", "s", "r") is not None
    clock.advance(61)
    assert reg.reason("j1", "s", "r") is None
    assert reg.revoke("jti", "j1", "leaked again") is True  # an expired entry can be re-revoked


def test_shield_blocks_a_revoked_token_without_touching_detector_state(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    sh = make_shield()
    token = mint(issuer, clock)
    assert sh.evaluate(ctx_for(token)).decision is Decision.ALLOW
    jti = sh._verifier.verify(token).jti
    sh.revocations.revoke("jti", jti, "key leaked in a log")
    ev = sh.evaluate(ctx_for(token))
    assert ev.decision is Decision.BLOCK
    assert ev.findings[0].rule_id == R_TOKEN_INVALID
    assert (
        "token revoked" in ev.findings[0].detail and "key leaked in a log" in ev.findings[0].detail
    )
    assert not sh.quarantine.is_quarantined("run-1")  # unauthenticated: no state, no quarantine
    fresh = mint(issuer, clock)
    assert sh.evaluate(ctx_for(fresh)).decision is Decision.ALLOW  # a new token is a new jti


def test_subject_and_run_revocation_cover_every_token_of_that_identity(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    sh = make_shield()
    sh.revocations.revoke("subject", "bad-svc", "compromised")
    sh.revocations.revoke("run", "run-stopped", "operator stop")
    for kw in ({"subject": "bad-svc", "agent_run_id": "r1"}, {"agent_run_id": "run-stopped"}):
        token = mint(issuer, clock, **kw)
        assert sh.evaluate(ctx_for(token, kw["agent_run_id"])).decision is Decision.BLOCK
    ok = mint(issuer, clock, subject="good", agent_run_id="r9")
    assert sh.evaluate(ctx_for(ok, "r9")).decision is Decision.ALLOW


def test_decorator_raises_token_invalid_for_a_revoked_token(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    sh = make_shield()
    sh.revocations.revoke("run", "run-1", "stop")
    guarded = sh.guard(_paid)
    with pytest.raises(TokenInvalidError, match="token revoked"):
        guarded(ctx=ctx_for(mint(issuer, clock)))


def test_journal_persists_and_is_shared_between_processes(tmp_path: Path, clock: FakeClock) -> None:
    journal = tmp_path / "revoked.jsonl"
    server = RevocationRegistry(journal, clock=clock.now, poll_seconds=0)
    assert server.reason("j", "s", "r") is None
    RevocationRegistry(journal, clock=clock.now).revoke("jti", "j", "from the CLI")
    assert "from the CLI" in (server.reason("j", "s", "r") or "")  # picked up while running
    assert "from the CLI" in (
        RevocationRegistry(journal, clock=clock.now).reason("j", "s", "r") or ""
    )


def test_polling_is_rate_limited(tmp_path: Path, clock: FakeClock) -> None:
    journal = tmp_path / "revoked.jsonl"
    tick = [0.0]
    server = RevocationRegistry(
        journal, clock=clock.now, poll_seconds=5.0, poll_clock=lambda: tick[0]
    )
    RevocationRegistry(journal, clock=clock.now).revoke("run", "r", "stop")
    assert server.reason("j", "s", "r") is None  # inside the polling interval
    tick[0] = 5.1
    assert server.reason("j", "s", "r") is not None


def test_a_partially_written_line_is_not_consumed_until_complete(
    tmp_path: Path, clock: FakeClock
) -> None:
    journal = tmp_path / "revoked.jsonl"
    reg = RevocationRegistry(journal, clock=clock.now, poll_seconds=0)
    full = json.dumps({"kind": "run", "value": "r", "reason": "stop", "expires_at": None})
    journal.write_text(full[:20], encoding="utf-8")  # a writer is mid-line
    assert reg.reason("j", "s", "r") is None
    journal.write_text(full + "\n", encoding="utf-8")
    assert reg.reason("j", "s", "r") is not None


def test_a_torn_line_is_skipped_and_does_not_swallow_the_next_revocation(
    tmp_path: Path, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    journal = tmp_path / "revoked.jsonl"
    journal.write_text('{"kind": "jti", "val', encoding="utf-8")  # crash mid-write, no newline
    with caplog.at_level(logging.WARNING):
        reg = RevocationRegistry(journal, clock=clock.now, poll_seconds=0)
        assert reg.revoke("jti", "j2", "after the crash")
        assert "after the crash" in (reg.reason("j2", "s", "r") or "")
        restarted = RevocationRegistry(journal, clock=clock.now)
        assert "after the crash" in (restarted.reason("j2", "s", "r") or "")
    assert "unreadable revocation journal line" in caplog.text
    journal.write_text('{"kind": "jti"}\n\n', encoding="utf-8")  # blank + incomplete record
    RevocationRegistry(journal, clock=clock.now)


def test_a_truncated_journal_starts_again(tmp_path: Path, clock: FakeClock) -> None:
    journal = tmp_path / "revoked.jsonl"
    reg = RevocationRegistry(journal, clock=clock.now, poll_seconds=0)
    reg.revoke("run", "r", "stop")
    assert reg.reason("j", "s", "r") is not None
    journal.write_text("", encoding="utf-8")
    assert reg.reason("j", "s", "r") is None
    assert (
        RevocationRegistry(tmp_path / "absent.jsonl", clock=clock.now).reason("j", "s", "r") is None
    )


def test_cli_revoke_reaches_a_running_shield(
    policy: PolicyConfig,
    verifier: Any,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    journal = tmp_path / "revoked.jsonl"
    sh = Shield(
        policy,
        verifier,
        revocations=RevocationRegistry(journal, clock=clock.now, poll_seconds=0),
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    token = mint(issuer, clock)
    assert sh.evaluate(ctx_for(token)).decision is Decision.ALLOW
    assert main(["revoke", str(journal), "--run", "run-1", "--reason", "operator stop"]) == 0
    assert "revoked run 'run-1'" in capsys.readouterr().out
    assert sh.evaluate(ctx_for(token)).decision is Decision.BLOCK
    assert main(["revoke", str(journal), "--run", "run-1", "--reason", "again"]) == 0
    assert "already revoked" in capsys.readouterr().out
    assert main(["revoke", str(journal), "--jti", "j", "--reason", "x", "--expires-in", "60"]) == 0
    with pytest.raises(SystemExit):
        main(["revoke", str(journal), "--reason", "no target given"])


def test_the_shield_builds_a_journaled_registry_from_the_policy(
    policy: PolicyConfig, verifier: Any, issuer: AgentTokenIssuer, clock: FakeClock, tmp_path: Path
) -> None:
    journal = tmp_path / "policy_revoked.jsonl"
    pol = policy.model_copy(update={"revocation_journal_path": journal})
    sh = Shield(pol, verifier, clock=clock.now, monotonic=clock.monotonic)
    sh.revocations.revoke("run", "run-1", "stop")
    assert journal.exists() and "stop" in journal.read_text(encoding="utf-8")
    assert sh.evaluate(ctx_for(mint(issuer, clock))).decision is Decision.BLOCK
