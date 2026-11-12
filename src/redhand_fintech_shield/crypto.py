"""Ed25519 ephemeral per-run agent tokens (compact JWS, ``alg=EdDSA``)."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from .exceptions import PolicyLoadError, TokenInvalidError
from .models import Env, TokenClaims

_ALG = "EdDSA"
_REQUIRED = (
    "iss",
    "sub",
    "agent_run_id",
    "env",
    "allowed_tools",
    "hitl_step_up",
    "iat",
    "exp",
    "jti",
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def private_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key_pem(path: str | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file; anything else is rejected."""
    p = Path(path)
    try:
        key = serialization.load_pem_public_key(p.read_bytes())
    except (OSError, ValueError, UnsupportedAlgorithm) as exc:
        raise PolicyLoadError(f"cannot load public key {p}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PolicyLoadError(f"public key {p} is not an Ed25519 key")
    return key


class AgentTokenIssuer:
    """Mints short-lived, least-privilege tokens bound to one agent run."""

    def __init__(self, signing_key: Ed25519PrivateKey, issuer: str = "redhand") -> None:
        self._key = signing_key
        self._issuer = issuer

    @staticmethod
    def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        private = Ed25519PrivateKey.generate()
        return private, private.public_key()

    def mint(
        self,
        *,
        subject: str,
        agent_run_id: str,
        env: Env,
        allowed_tools: Sequence[str],
        ttl_seconds: int = 900,
        hitl_step_up: bool = False,
        now: datetime | None = None,
    ) -> str:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        issued = int((now or utcnow()).timestamp())
        payload = {
            "iss": self._issuer,
            "sub": subject,
            "agent_run_id": agent_run_id,
            "env": Env(env).value,
            "allowed_tools": list(allowed_tools),
            "hitl_step_up": hitl_step_up,
            "iat": issued,
            "exp": issued + ttl_seconds,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self._key, algorithm=_ALG)


class AgentTokenVerifier:
    """Verifies tokens. Expiry uses an injectable clock so tests never sleep."""

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        issuer: str = "redhand",
        *,
        max_ttl_seconds: int = 3600,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._key = public_key
        self._issuer = issuer
        self._max_ttl = max_ttl_seconds
        self._clock = clock

    def verify(self, token: str) -> TokenClaims:
        """Return verified claims or raise :class:`TokenInvalidError`.

        The algorithm is pinned to EdDSA, so ``alg=none`` and HMAC-confusion tokens fail.
        """
        try:
            raw = jwt.decode(
                token,
                self._key,
                algorithms=[_ALG],
                issuer=self._issuer,
                options={
                    "require": list(_REQUIRED),
                    "verify_exp": False,  # checked below against the injectable clock
                    "verify_iat": False,
                },
            )
            claims = TokenClaims.model_validate(raw)
        except (jwt.PyJWTError, ValidationError, ValueError, TypeError) as exc:
            raise TokenInvalidError(f"token rejected: {type(exc).__name__}") from exc

        now = int(self._clock().timestamp())
        if claims.exp <= now:
            raise TokenInvalidError("token expired")
        if claims.iat > now + 5:
            raise TokenInvalidError("token issued in the future")
        if claims.exp - claims.iat > self._max_ttl:
            raise TokenInvalidError("token lifetime exceeds policy maximum")
        return claims
