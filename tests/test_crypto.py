from __future__ import annotations

from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    Env,
    PolicyLoadError,
    TokenInvalidError,
)
from redhand_fintech_shield.crypto import load_public_key_pem, private_key_to_pem, public_key_to_pem

from .conftest import FakeClock


def mint(issuer: AgentTokenIssuer, clock: FakeClock, **kw: object) -> str:
    args: dict[str, object] = {
        "subject": "svc",
        "agent_run_id": "run-1",
        "env": Env.PROD,
        "allowed_tools": ["charge_card"],
        "now": clock.now(),
    }
    args.update(kw)
    return issuer.mint(**args)  # type: ignore[arg-type]


def test_roundtrip_exposes_all_claims(
    issuer: AgentTokenIssuer, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    claims = verifier.verify(mint(issuer, clock, hitl_step_up=True))
    assert claims.sub == "svc"
    assert claims.agent_run_id == "run-1"
    assert claims.env is Env.PROD
    assert claims.allowed_tools == ("charge_card",)
    assert claims.hitl_step_up is True
    assert claims.exp - claims.iat == 900
    assert claims.iss == "redhand"
    assert claims.jti


def test_each_token_has_unique_jti(issuer: AgentTokenIssuer, clock: FakeClock) -> None:
    a = jwt.decode(mint(issuer, clock), options={"verify_signature": False})
    b = jwt.decode(mint(issuer, clock), options={"verify_signature": False})
    assert a["jti"] != b["jti"]


def test_header_is_eddsa(issuer: AgentTokenIssuer, clock: FakeClock) -> None:
    assert jwt.get_unverified_header(mint(issuer, clock))["alg"] == "EdDSA"


def test_expired_token_rejected(
    issuer: AgentTokenIssuer, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    token = mint(issuer, clock, ttl_seconds=10)
    clock.advance(11)
    with pytest.raises(TokenInvalidError, match="expired"):
        verifier.verify(token)


def test_future_dated_token_rejected(
    issuer: AgentTokenIssuer, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    token = mint(issuer, clock)
    clock.advance(-600)
    with pytest.raises(TokenInvalidError, match="future"):
        verifier.verify(token)


def test_overlong_ttl_rejected(
    issuer: AgentTokenIssuer, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    with pytest.raises(TokenInvalidError, match="lifetime"):
        verifier.verify(mint(issuer, clock, ttl_seconds=7200))


def test_wrong_signing_key_rejected(verifier: AgentTokenVerifier, clock: FakeClock) -> None:
    rogue = AgentTokenIssuer(Ed25519PrivateKey.generate())
    with pytest.raises(TokenInvalidError):
        verifier.verify(mint(rogue, clock))


def test_tampered_payload_rejected(
    issuer: AgentTokenIssuer, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    head, _, sig = mint(issuer, clock, env=Env.STAGING).split(".")
    forged = jwt.encode(
        {
            "iss": "redhand",
            "sub": "svc",
            "agent_run_id": "run-1",
            "env": "prod",
            "allowed_tools": ["*"],
            "hitl_step_up": True,
            "iat": 0,
            "exp": 9999999999,
            "jti": "x",
        },
        "k" * 32,
        algorithm="HS256",
    ).split(".")[1]
    with pytest.raises(TokenInvalidError):
        verifier.verify(f"{head}.{forged}.{sig}")


def test_alg_none_rejected(verifier: AgentTokenVerifier, clock: FakeClock) -> None:
    now = int(clock.now().timestamp())
    token = jwt.encode(
        {
            "iss": "redhand",
            "sub": "s",
            "agent_run_id": "run-1",
            "env": "prod",
            "allowed_tools": ["x"],
            "hitl_step_up": True,
            "iat": now,
            "exp": now + 60,
            "jti": "j",
        },
        None,  # type: ignore[arg-type]
        algorithm="none",
    )
    with pytest.raises(TokenInvalidError):
        verifier.verify(token)


def test_hmac_algorithm_confusion_rejected(verifier: AgentTokenVerifier, clock: FakeClock) -> None:
    now = int(clock.now().timestamp())
    token = jwt.encode(
        {
            "iss": "redhand",
            "sub": "s",
            "agent_run_id": "run-1",
            "env": "prod",
            "allowed_tools": ["x"],
            "hitl_step_up": True,
            "iat": now,
            "exp": now + 60,
            "jti": "j",
        },
        "attacker-chosen-secret-0123456789abcdef",
        algorithm="HS256",
    )
    with pytest.raises(TokenInvalidError):
        verifier.verify(token)


def test_wrong_issuer_rejected(
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey], clock: FakeClock
) -> None:
    other = AgentTokenIssuer(keypair[0], issuer="someone-else")
    with pytest.raises(TokenInvalidError):
        AgentTokenVerifier(keypair[1], clock=clock.now).verify(mint(other, clock))


def test_missing_claim_rejected(
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    verifier: AgentTokenVerifier,
    clock: FakeClock,
) -> None:
    now = int(clock.now().timestamp())
    token = jwt.encode(
        {"iss": "redhand", "sub": "s", "env": "prod", "iat": now, "exp": now + 60},
        keypair[0],
        algorithm="EdDSA",
    )
    with pytest.raises(TokenInvalidError):
        verifier.verify(token)


def test_garbage_rejected(verifier: AgentTokenVerifier) -> None:
    for junk in ("", "not-a-jwt", "a.b.c"):
        with pytest.raises(TokenInvalidError):
            verifier.verify(junk)


def test_non_positive_ttl_refused_at_mint(issuer: AgentTokenIssuer) -> None:
    with pytest.raises(ValueError):
        issuer.mint(subject="s", agent_run_id="r", env=Env.DEV, allowed_tools=[], ttl_seconds=0)


def test_pem_roundtrip_and_key_type_enforced(
    tmp_path: Path, keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey]
) -> None:
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(public_key_to_pem(keypair[1]))
    assert load_public_key_pem(pub_path).public_bytes_raw() == keypair[1].public_bytes_raw()
    assert b"PRIVATE KEY" in private_key_to_pem(keypair[0])

    from cryptography.hazmat.primitives import serialization

    rsa_pub = generate_private_key(65537, 2048).public_key()
    rsa_path = tmp_path / "rsa.pem"
    rsa_path.write_bytes(
        rsa_pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(PolicyLoadError):
        load_public_key_pem(rsa_path)
    with pytest.raises(PolicyLoadError):
        load_public_key_pem(tmp_path / "missing.pem")
