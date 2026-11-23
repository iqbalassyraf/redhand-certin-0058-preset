"""Per-transaction step-up: signed, single-use approvals bound to one exact transaction.

The run-wide ``hitl_step_up`` token claim pre-authorises everything a run does. An approval
authorises one transaction: it is signed by an approver key that is separate from the agent-token
issuer, names the run, tool, environment, amount, currency, every beneficiary and a digest of the
exact arguments, expires within minutes and carries a nonce that can be spent once.

An approval is a compact JWS (``alg=EdDSA``, ``typ=redhand-approval+jwt``). Nothing here calls the
network or a model; verification is a signature check, a clock check and a field-by-field compare.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from .crypto import utcnow
from .models import ApprovalClaims, ApprovalRequest, ToolCallContext

_log = logging.getLogger(__name__)

APPROVAL_TYP = "redhand-approval+jwt"
_ALG = "EdDSA"
_REQUIRED = (
    "iss",
    "sub",
    "request_id",
    "agent_run_id",
    "tool_name",
    "target_env",
    "nonce",
    "iat",
    "exp",
)
_CLOCK_SKEW_SECONDS = 5


def arguments_digest(arguments: dict[str, Any]) -> str | None:
    """SHA-256 of the canonical JSON of the (sanitised) tool arguments, or None if not encodable.

    Objects that are not JSON are stringified, which can make the digest differ between calls; an
    approval then simply fails to match (fail-closed), it is never accepted wrongly.
    """
    try:
        blob = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def payees_of(ctx: ToolCallContext) -> tuple[str, ...]:
    """Every payee of the call, deduplicated and sorted, so order never changes what is signed."""
    names = set(ctx.beneficiaries)
    if ctx.beneficiary:
        names.add(ctx.beneficiary)
    return tuple(sorted(names))


def build_request(
    ctx: ToolCallContext, reasons: tuple[str, ...], details: tuple[str, ...], now: datetime
) -> ApprovalRequest:
    """The request a human is asked to approve for ``ctx``."""
    return ApprovalRequest(
        request_id=str(uuid.uuid4()),
        agent_run_id=ctx.agent_run_id,
        tool_name=ctx.tool_name,
        target_env=ctx.target_env,
        amount=ctx.amount,
        currency=ctx.currency,
        beneficiaries=payees_of(ctx),
        arguments_digest=ctx.arguments_digest,
        reasons=reasons,
        details=details,
        requested_at=now.astimezone(UTC),
    )


class ApprovalIssuer:
    """Signs approvals. Lives with the approver (a human-facing service), never with the agent."""

    def __init__(self, signing_key: Ed25519PrivateKey, issuer: str = "redhand-approver") -> None:
        self._key = signing_key
        self._issuer = issuer

    def grant(
        self,
        request: ApprovalRequest,
        *,
        approver: str,
        ttl_seconds: int = 120,
        now: datetime | None = None,
    ) -> str:
        """Approve exactly ``request``. The approval is useless for any other transaction."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if not approver.strip():
            raise ValueError("approver must name who approved")
        issued = int((now or utcnow()).timestamp())
        payload = {
            "iss": self._issuer,
            "sub": approver,
            "request_id": request.request_id,
            "agent_run_id": request.agent_run_id,
            "tool_name": request.tool_name,
            "target_env": request.target_env.value,
            "amount": None if request.amount is None else str(request.amount),
            "currency": request.currency,
            "beneficiaries": sorted(request.beneficiaries),
            "arguments_digest": request.arguments_digest,
            "nonce": str(uuid.uuid4()),
            "iat": issued,
            "exp": issued + ttl_seconds,
        }
        return jwt.encode(payload, self._key, algorithm=_ALG, headers={"typ": APPROVAL_TYP})


class ApprovalVerifier:
    """Verifies the signature, lifetime and issuer of an approval. Binding is checked separately."""

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        issuer: str = "redhand-approver",
        *,
        max_ttl_seconds: int = 300,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._key = public_key
        self._issuer = issuer
        self._max_ttl = max_ttl_seconds
        self._clock = clock

    @property
    def key_fingerprints(self) -> frozenset[str]:
        return frozenset({self.key_fingerprint})

    @property
    def key_fingerprint(self) -> str:
        raw = self._key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return hashlib.sha256(raw).hexdigest()

    def verify(self, approval: str) -> ApprovalClaims:
        """Return verified claims or raise ``ValueError`` with a reason safe to log."""
        try:
            header = jwt.get_unverified_header(approval)
            if header.get("typ") != APPROVAL_TYP:
                raise ValueError("not an approval (wrong typ)")
            raw = jwt.decode(
                approval,
                self._key,
                algorithms=[_ALG],
                issuer=self._issuer,
                options={"require": list(_REQUIRED), "verify_exp": False, "verify_iat": False},
            )
            claims = ApprovalClaims.model_validate(raw)
        except (jwt.PyJWTError, ValidationError, TypeError) as exc:
            raise ValueError(f"approval rejected: {type(exc).__name__}") from exc

        now = int(self._clock().timestamp())
        if claims.exp <= now:
            raise ValueError("approval expired")
        if claims.iat > now + _CLOCK_SKEW_SECONDS:
            raise ValueError("approval issued in the future")
        if claims.exp - claims.iat > self._max_ttl:
            raise ValueError("approval lifetime exceeds policy maximum")
        return claims


def binding_mismatch(claims: ApprovalClaims, ctx: ToolCallContext) -> str | None:
    """Return why ``claims`` does not authorise ``ctx``, or None if every binding matches."""
    if claims.agent_run_id != ctx.agent_run_id:
        return "approval is for a different agent run"
    if claims.tool_name != ctx.tool_name:
        return "approval is for a different tool"
    if claims.target_env != ctx.target_env:
        return "approval is for a different environment"
    if claims.currency != ctx.currency:
        return "approval is for a different currency"
    try:
        approved = None if claims.amount is None else Decimal(claims.amount)
    except InvalidOperation:
        return "approval carries an unreadable amount"
    if approved != ctx.amount:
        return "approval is for a different amount"
    if tuple(sorted(claims.beneficiaries)) != payees_of(ctx):
        return "approval is for different beneficiaries"
    if claims.arguments_digest != ctx.arguments_digest:
        return "approval is for different arguments"
    return None


class NonceRegistry:
    """In-memory single-use ledger with an optional journal so a restart cannot re-open nonces."""

    def __init__(
        self,
        journal_path: Path | None = None,
        *,
        max_entries: int = 100_000,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._lock = threading.Lock()
        self._spent: dict[str, int] = {}
        self._max = max_entries
        self._clock = clock
        self._journal_path = journal_path
        if journal_path is not None:
            self._replay(journal_path)

    def _now(self) -> int:
        return int(self._clock().timestamp())

    def _replay(self, path: Path) -> None:
        if not path.exists():
            return
        now = self._now()
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    nonce, exp = str(entry["nonce"]), int(entry["exp"])
                except (ValueError, KeyError, TypeError):
                    _log.warning("ignoring unreadable nonce journal line %s:%d", path, lineno)
                    continue
                if exp > now:
                    self._spent[nonce] = exp

    def _purge(self, now: int) -> None:
        for nonce in [n for n, exp in self._spent.items() if exp <= now]:
            del self._spent[nonce]

    def consume(self, nonce: str, expires_at: int) -> bool:
        with self._lock:
            now = self._now()
            if nonce in self._spent and self._spent[nonce] > now:
                return False
            if len(self._spent) >= self._max:
                self._purge(now)
                if len(self._spent) >= self._max:
                    return False  # full of live nonces: fail closed rather than forget one
            if self._journal_path is not None:
                line = json.dumps({"nonce": nonce, "exp": expires_at}, separators=(",", ":"))
                with self._journal_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            self._spent[nonce] = expires_at
            return True

    def __len__(self) -> int:
        return len(self._spent)
