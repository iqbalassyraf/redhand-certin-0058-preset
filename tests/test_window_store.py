"""Phase 3.5 E: the WindowStore protocol and the detector state backend.

Rationale: a host that runs several workers must be able to put detector state somewhere shared.
The protocol is only a real seam if (a) a backend can be checked against it, (b) an independent
implementation behaves like the default under the same detector tests (see the ``window_backend``
fixture), and (c) the limits of sharing are stated, not discovered in production.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from decimal import Decimal
from typing import Any

import pytest

from redhand_fintech_shield import (
    AgentTokenIssuer,
    Decision,
    Env,
    PolicyConfig,
    Shield,
    ToolCallContext,
)
from redhand_fintech_shield.detectors import (
    NS_CAP,
    CumulativeCapDetector,
    InMemoryWindowStore,
    OffHoursEvaluator,
)
from redhand_fintech_shield.models import CumulativeCapPolicy
from redhand_fintech_shield.protocols import WindowStore, WindowStoreFull
from redhand_fintech_shield.testing import window_store_contract
from redhand_fintech_shield.windowstore import default_window_store
from tests.conftest import BUSINESS_HOURS_UTC, PRESET, FakeClock
from tests.window_stores import ListWindowStore

TOOL = "settle_merchant"


# --------------------------------------------------------------------------------------
# The contract kit
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("factory", "bounded"),
    [
        (InMemoryWindowStore, lambda n: InMemoryWindowStore(max_keys={"contract.sums": n})),
        (ListWindowStore, lambda n: ListWindowStore(max_keys={"contract.sums": n})),
    ],
    ids=["in-memory", "list"],
)
def test_both_stores_satisfy_the_contract(
    factory: Callable[[], WindowStore], bounded: Callable[[int], WindowStore]
) -> None:
    window_store_contract(factory, make_bounded=bounded)
    window_store_contract(factory)  # the bounded checks are optional


def test_stores_implement_the_protocol() -> None:
    assert isinstance(InMemoryWindowStore(), WindowStore)
    assert isinstance(ListWindowStore(), WindowStore)
    assert isinstance(default_window_store(), InMemoryWindowStore)


class BrokenStore(InMemoryWindowStore):
    """Each subclass breaks one rule the detectors rely on."""

    mode = ""

    def hit(self, namespace: str, key: tuple[str, ...], now: float, **kw: Any) -> int:
        count = super().hit(namespace, key, now, **kw)
        return count + 1 if self.mode == "off_by_one" else count

    def count(self, namespace: str, key: tuple[str, ...], now: float, **kw: Any) -> int:
        if self.mode == "count_records":
            super().hit(namespace, key, now, window=kw["window"], maxlen=99)
        return super().count(namespace, key, now, **kw)

    def add(
        self, namespace: str, key: tuple[str, ...], now: float, amount: Decimal, **kw: Any
    ) -> Any:
        if self.mode == "float_sums":
            amount = Decimal(float(amount))
        entries, total, saturated = super().add(namespace, key, now, amount, **kw)
        return (
            (entries, total, False)
            if self.mode == "hide_saturation"
            else (entries, total, saturated)
        )

    def has_room(
        self, namespace: str, keys: Sequence[tuple[str, ...]], now: float, **kw: Any
    ) -> bool:
        return True if self.mode == "never_full" else super().has_room(namespace, keys, now, **kw)


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("off_by_one", "hit must return the number of events"),
        ("count_records", "count"),
        ("hide_saturation", "saturated=True"),
        ("never_full", "a full store must report no room"),
    ],
)
def test_the_contract_catches_a_backend_that_gets_it_wrong(mode: str, message: str) -> None:
    def make() -> BrokenStore:
        store = BrokenStore(max_keys={"contract.sums": 2})
        store.mode = mode
        return store

    with pytest.raises(AssertionError, match=message):
        window_store_contract(make, make_bounded=lambda n: make())


def test_the_contract_catches_a_store_that_never_raises_when_full() -> None:
    class NeverRaises(InMemoryWindowStore):
        def add(
            self, namespace: str, key: tuple[str, ...], now: float, amount: Decimal, **kw: Any
        ) -> Any:
            try:
                return super().add(namespace, key, now, amount, **kw)
            except WindowStoreFull:
                return (1, amount, False)

        def has_room(
            self, namespace: str, keys: Sequence[tuple[str, ...]], now: float, **kw: Any
        ) -> bool:
            return super().has_room(namespace, keys, now, **kw)

    with pytest.raises(AssertionError, match="must raise"):
        window_store_contract(
            lambda: NeverRaises(), make_bounded=lambda n: NeverRaises(max_keys={"contract.sums": n})
        )


# --------------------------------------------------------------------------------------
# The in-memory store itself
# --------------------------------------------------------------------------------------


def test_namespaces_do_not_share_windows_or_key_limits() -> None:
    store = InMemoryWindowStore(max_keys={"a": 1})
    store.add("a", ("k",), 0.0, Decimal(1), window=10, maxlen=5)
    with pytest.raises(WindowStoreFull):
        store.add("a", ("other",), 0.0, Decimal(1), window=10, maxlen=5)
    store.add("b", ("k",), 0.0, Decimal(1), window=10, maxlen=5)  # another namespace: no limit
    store.add("b", ("k2",), 0.0, Decimal(1), window=10, maxlen=5)
    assert store.hit("a", ("k",), 0.0, window=10, maxlen=5) == 1  # counters are separate from sums
    assert store.count("never", ("k",), 0.0, window=10) == 0
    assert store.has_room("never", [("k",)], 0.0, window=10)


# --------------------------------------------------------------------------------------
# Sharing a store between shields, and the limits of doing so
# --------------------------------------------------------------------------------------


def _shield(
    policy: PolicyConfig, verifier: Any, clock: FakeClock, store: WindowStore | None
) -> Shield:
    capped = policy.model_copy(
        update={
            "structuring": policy.structuring.model_copy(update={"enabled": False}),
            "cumulative_cap": CumulativeCapPolicy(
                enabled=True,
                protected_tools=frozenset({TOOL}),
                per_run={"USD": Decimal("10000")},
                per_subject={"USD": Decimal("10000")},
            ),
        }
    )
    return Shield(
        capped,
        verifier,
        window_store=store,
        clock=clock.now,
        monotonic=clock.monotonic,
    )


def _pay(issuer: AgentTokenIssuer, clock: FakeClock, run: str) -> ToolCallContext:
    token = issuer.mint(
        subject="svc", agent_run_id=run, env=Env.PROD, allowed_tools=(TOOL,), now=clock.now()
    )
    return ToolCallContext(
        agent_run_id=run,
        tool_name=TOOL,
        target_env=Env.PROD,
        token=token,
        amount=Decimal("6000"),
        currency="USD",
    )


@pytest.mark.parametrize("kind", ["memory", "list"])
def test_two_workers_sharing_a_store_share_the_subject_cap(
    kind: str, policy: PolicyConfig, verifier: Any, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    def make_store() -> WindowStore:
        limits = {NS_CAP: 1000}
        return (
            ListWindowStore(max_keys=limits)
            if kind == "list"
            else InMemoryWindowStore(max_keys=limits)
        )

    shared = make_store()
    worker_a = _shield(policy, verifier, clock, shared)
    worker_b = _shield(policy, verifier, clock, shared)
    assert worker_a.evaluate(_pay(issuer, clock, "run-a")).decision is Decision.ALLOW
    # worker B has never seen this subject, yet the shared window already holds A's 6,000
    over = worker_b.evaluate(_pay(issuer, clock, "run-b"))
    assert over.decision is Decision.HITL_REQUIRED

    isolated_a = _shield(policy, verifier, clock, None)
    isolated_b = _shield(policy, verifier, clock, None)
    assert isolated_a.evaluate(_pay(issuer, clock, "run-a2")).decision is Decision.ALLOW
    assert isolated_b.evaluate(_pay(issuer, clock, "run-b2")).decision is Decision.ALLOW  # the gap


def test_a_shield_without_a_store_builds_one_from_the_policy_limits(
    policy: PolicyConfig, verifier: Any, clock: FakeClock
) -> None:
    sh = Shield(policy, verifier, clock=clock.now, monotonic=clock.monotonic)
    assert isinstance(sh.window_store, InMemoryWindowStore)
    mine = ListWindowStore()
    assert Shield(policy, verifier, window_store=mine, clock=clock.now).window_store is mine


def test_a_full_store_fails_closed_through_the_shield(
    policy: PolicyConfig, verifier: Any, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    tiny = _shield(policy, verifier, clock, InMemoryWindowStore(max_keys={NS_CAP: 2}))
    assert tiny.evaluate(_pay(issuer, clock, "run-1")).decision is Decision.ALLOW  # run + subject
    other = _pay(issuer, clock, "run-2")
    ev = tiny.evaluate(other.model_copy(update={"amount": Decimal("1")}))
    # the subject window exists; the new run needs a third key, which the store refuses
    assert ev.decision is Decision.HITL_REQUIRED
    assert any("tracker is full" in f.detail for f in ev.findings)


def test_a_store_that_fills_between_check_and_record_is_logged_not_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FillsAfterCheck(InMemoryWindowStore):
        def add(self, *args: Any, **kwargs: Any) -> Any:
            raise WindowStoreFull("full")

    policy = CumulativeCapPolicy(enabled=True, per_run={"USD": Decimal("100")})
    detector = CumulativeCapDetector(policy, store=FillsAfterCheck())
    effective = OffHoursEvaluator(PolicyConfig(cumulative_cap=policy)).effective(BUSINESS_HOURS_UTC)
    assert detector.check("r", TOOL, Decimal("10"), "USD", 0.0, effective) is None
    with caplog.at_level(logging.ERROR):
        detector.record("r", TOOL, Decimal("10"), "USD", 0.0)
    assert "payment for run not counted" in caplog.text


def test_shield_accepts_the_preset_unchanged_with_any_store(
    verifier: Any, clock: FakeClock, issuer: AgentTokenIssuer
) -> None:
    sh = Shield(
        PolicyConfig.from_yaml(PRESET).model_copy(update={"audit_path": PRESET.parent / "unused"}),
        verifier,
        window_store=ListWindowStore(),
        audit=_NullAudit(),
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    ctx = ToolCallContext(
        agent_run_id="r",
        tool_name="charge_card",
        target_env=Env.PROD,
        token=issuer.mint(
            subject="s",
            agent_run_id="r",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            now=clock.now(),
        ),
        amount=Decimal("100"),
        currency="USD",
    )
    assert sh.evaluate(ctx).decision is Decision.ALLOW


class _NullAudit:
    tail_hash = "0" * 64

    def append(self, body: dict[str, Any]) -> Any:
        return None

    def close(self) -> None:
        return None


def test_a_payment_that_needs_two_new_keys_is_refused_when_only_one_fits(
    policy: PolicyConfig, verifier: Any, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    """The run and subject windows are stored together or not at all (no silent undercount)."""
    one_slot = _shield(policy, verifier, clock, InMemoryWindowStore(max_keys={NS_CAP: 1}))
    ev = one_slot.evaluate(_pay(issuer, clock, "run-1"))
    assert ev.decision is Decision.HITL_REQUIRED
    assert any("tracker is full" in f.detail for f in ev.findings)
    assert one_slot.window_store.snapshot(NS_CAP, ("run", "run-1", "USD"), 0.0, window=1.0)[0] == 0
