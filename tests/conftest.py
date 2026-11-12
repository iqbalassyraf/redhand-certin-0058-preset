"""Shared fixtures: a controllable clock, key material, and a ready-to-use Shield factory."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from redhand_fintech_shield.crypto import AgentTokenIssuer, AgentTokenVerifier
from redhand_fintech_shield.interceptor import Shield
from redhand_fintech_shield.models import Env, Mode, PolicyConfig, ToolCallContext

PRESET = Path(__file__).resolve().parent.parent / "presets" / "certin_ciad_2026_0058.yaml"

# Wednesday 2026-11-11 11:00 IST == 05:30 UTC: inside business hours.
BUSINESS_HOURS_UTC = datetime(2026, 11, 11, 5, 30, tzinfo=UTC)
# Saturday 2026-11-14 11:00 IST == 05:30 UTC: weekend.
WEEKEND_UTC = datetime(2026, 11, 14, 5, 30, tzinfo=UTC)


class FakeClock:
    """Wall clock + monotonic clock that advance together; no sleeping in tests."""

    def __init__(self, start: datetime = BUSINESS_HOURS_UTC) -> None:
        self.wall = start
        self.mono = 1000.0

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    return AgentTokenIssuer.generate_keypair()


@pytest.fixture
def issuer(keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey]) -> AgentTokenIssuer:
    return AgentTokenIssuer(keypair[0])


@pytest.fixture
def verifier(
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey], clock: FakeClock
) -> AgentTokenVerifier:
    return AgentTokenVerifier(keypair[1], clock=clock.now)


@pytest.fixture
def policy(tmp_path: Path) -> PolicyConfig:
    base = PolicyConfig.from_yaml(PRESET)
    return base.model_copy(
        update={
            "audit_path": tmp_path / "audit_trail.jsonl",
            "quarantine_journal_path": tmp_path / "quarantine.jsonl",
        }
    )


@pytest.fixture
def make_shield(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock
) -> Callable[..., Shield]:
    def _make(mode: Mode = Mode.ENFORCE, **policy_updates: Any) -> Shield:
        pol = policy.model_copy(update={"mode": mode, **policy_updates})
        return Shield(pol, verifier, clock=clock.now, monotonic=clock.monotonic)

    return _make


@pytest.fixture
def shield(make_shield: Callable[..., Shield]) -> Shield:
    return make_shield()


@pytest.fixture
def make_ctx(issuer: AgentTokenIssuer, clock: FakeClock) -> Callable[..., ToolCallContext]:
    """Build a context with a freshly minted, valid token unless one is supplied."""

    def _make(
        *,
        run: str = "run-1",
        tool: str = "charge_card",
        env: Env = Env.PROD,
        token_env: Env | None = None,
        allowed: tuple[str, ...] | None = None,
        hitl: bool = False,
        amount: str | None = None,
        currency: str | None = "USD",
        token: str | None = None,
    ) -> ToolCallContext:
        if token is None:
            token = issuer.mint(
                subject="svc-agent",
                agent_run_id=run,
                env=token_env or env,
                allowed_tools=allowed
                if allowed is not None
                else (
                    "charge_card",
                    "list_merchants",
                    "settle_merchant",
                    "initiate_disbursement",
                    "bulk_payout",
                ),
                hitl_step_up=hitl,
                now=clock.now(),
            )
        return ToolCallContext(
            agent_run_id=run,
            tool_name=tool,
            target_env=env,
            token=token,
            amount=Decimal(amount) if amount is not None else None,
            currency=currency if amount is not None else None,
        )

    return _make
