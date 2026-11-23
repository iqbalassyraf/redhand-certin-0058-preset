"""Ed25519 ephemeral per-run agent tokens (compact JWS, ``alg=EdDSA``)."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
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


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    """SHA-256 of the raw public key (keeps token and approval keys apart)."""
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class TokenKey:
    """One verification key: tokens name it by ``kid``; it stops verifying at ``retire_at``."""

    kid: str
    public_key: Ed25519PublicKey
    retire_at: datetime | None = None


class KeyRing:
    """Verification keys by ``kid``, so the signing key can be rotated with an overlap window.

    Publish the new key, start signing with it, and set ``retire_at`` on the old key to the time
    its last token can expire; after that instant tokens signed with it are refused.
    """

    def __init__(self, keys: Sequence[TokenKey]) -> None:
        if not keys:
            raise ValueError("a key ring needs at least one key")
        self._keys: dict[str, TokenKey] = {}
        for key in keys:
            if key.kid in self._keys:
                raise ValueError(f"duplicate kid {key.kid!r}")
            self._keys[key.kid] = key

    def get(self, kid: str) -> TokenKey | None:
        return self._keys.get(kid)

    @property
    def fingerprints(self) -> frozenset[str]:
        return frozenset(public_key_fingerprint(k.public_key) for k in self._keys.values())

    def __len__(self) -> int:
        return len(self._keys)


class AgentTokenIssuer:
    """Mints short-lived, least-privilege tokens bound to one agent run."""

    def __init__(
        self, signing_key: Ed25519PrivateKey, issuer: str = "redhand", *, kid: str | None = None
    ) -> None:
        self._key = signing_key
        self._issuer = issuer
        self._kid = kid

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
        audience: str | None = None,
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
        if audience is not None:
            payload["aud"] = audience
        headers = {"kid": self._kid} if self._kid is not None else None
        return jwt.encode(payload, self._key, algorithm=_ALG, headers=headers)


class AgentTokenVerifier:
    """Verifies tokens. Expiry uses an injectable clock so tests never sleep."""

    def __init__(
        self,
        public_key: Ed25519PublicKey | KeyRing,
        issuer: str = "redhand",
        *,
        max_ttl_seconds: int = 3600,
        clock: Callable[[], datetime] = utcnow,
        audience: str | None = None,
    ) -> None:
        self._ring = public_key if isinstance(public_key, KeyRing) else None
        self._key = None if isinstance(public_key, KeyRing) else public_key
        self._issuer = issuer
        self._max_ttl = max_ttl_seconds
        self._clock = clock
        self._audience = audience

    @property
    def key_fingerprints(self) -> frozenset[str]:
        """SHA-256 of every raw public key, used to keep token and approval keys separate."""
        if self._ring is not None:
            return self._ring.fingerprints
        assert self._key is not None
        return frozenset({public_key_fingerprint(self._key)})

    @property
    def key_fingerprint(self) -> str:
        """The fingerprint of the single verification key (not available with a key ring)."""
        if self._ring is not None:
            raise AttributeError("a key ring has several keys; use key_fingerprints")
        return next(iter(self.key_fingerprints))

    def _select_key(self, token: str) -> Ed25519PublicKey:
        if self._ring is None:
            assert self._key is not None
            return self._key
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise TokenInvalidError(f"token rejected: {type(exc).__name__}") from exc
        if not isinstance(kid, str):
            raise TokenInvalidError("token names no key id (kid)")
        entry = self._ring.get(kid)
        if entry is None:
            raise TokenInvalidError("token is signed with an unknown key id")
        if entry.retire_at is not None and self._clock() >= entry.retire_at:
            raise TokenInvalidError("token signing key has been retired")
        return entry.public_key

    def verify(self, token: str) -> TokenClaims:
        """Return verified claims or raise :class:`TokenInvalidError`.

        The algorithm is pinned to EdDSA, so ``alg=none`` and HMAC-confusion tokens fail.
        """
        key = self._select_key(token)
        required = [*_REQUIRED, "aud"] if self._audience is not None else list(_REQUIRED)
        try:
            raw = jwt.decode(
                token,
                key,
                algorithms=[_ALG],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": required,
                    "verify_exp": False,  # checked below against the injectable clock
                    "verify_iat": False,
                    # With no audience configured a token's aud is not checked, so tokens that
                    # carry one still verify; configure `audience` to bind tokens to this service.
                    "verify_aud": self._audience is not None,
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
