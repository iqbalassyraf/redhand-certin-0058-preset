"""Conformance checks for a host application's own ``WindowStore`` backend.

Run :func:`window_store_contract` against your backend in your test suite. It checks the behaviour
the detectors rely on: window expiry, the ``maxlen`` cap, saturation reporting, exact Decimal sums,
key and namespace isolation, read-only ``count``/``snapshot``, and (for a bounded store) the
fail-closed ``WindowStoreFull`` / ``has_room`` pair::

    def test_my_store_conforms():
        window_store_contract(
            lambda: MyRedisStore(...),
            make_bounded=lambda n: MyRedisStore(max_keys=n),
        )

It only checks single-caller semantics; atomicity under concurrency is the backend's job.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal

from .protocols import WindowStore, WindowStoreFull

WINDOW = 10.0
HITS = "contract.hits"
SUMS = "contract.sums"


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"WindowStore contract: {message}")


def window_store_contract(
    make_store: Callable[[], WindowStore],
    *,
    make_bounded: Callable[[int], WindowStore] | None = None,
) -> None:
    """Raise ``AssertionError`` naming the first behaviour ``make_store()`` gets wrong.

    ``make_bounded(n)`` should return a store that holds at most ``n`` distinct keys per
    namespace; supply it if your backend has such a limit.
    """
    _counters(make_store)
    _sums(make_store)
    _isolation(make_store)
    if make_bounded is not None:
        _bounded(make_bounded)


def _counters(make_store: Callable[[], WindowStore]) -> None:
    s = make_store()
    k = ("run-1",)
    _check(s.count(HITS, k, 0.0, window=WINDOW) == 0, "count of an unknown key must be 0")
    _check(
        [s.hit(HITS, k, t, window=WINDOW, maxlen=50) for t in (0.0, 1.0, 2.0)] == [1, 2, 3],
        "hit must return the number of events in the window, including the new one",
    )
    _check(s.count(HITS, k, 2.0, window=WINDOW) == 3, "count must see the recorded hits")
    _check(s.count(HITS, k, 2.0, window=WINDOW) == 3, "count must not record anything")
    # an event exactly `window` seconds old is expired
    _check(
        s.hit(HITS, k, 10.0, window=WINDOW, maxlen=50) == 3, "an event aged `window` must expire"
    )
    _check(s.count(HITS, k, 100.0, window=WINDOW) == 0, "everything must expire eventually")

    capped = make_store()
    got = [capped.hit(HITS, k, float(t), window=WINDOW, maxlen=3) for t in range(6)]
    _check(got == [1, 2, 3, 3, 3, 3], f"hit must cap at maxlen (got {got})")


def _sums(make_store: Callable[[], WindowStore]) -> None:
    s = make_store()
    k = ("run", "r1", "USD")
    _check(
        s.snapshot(SUMS, k, 0.0, window=WINDOW) == (0, Decimal(0)),
        "snapshot of an unknown key must be (0, 0)",
    )
    first = s.add(SUMS, k, 0.0, Decimal("0.1"), window=WINDOW, maxlen=50)
    second = s.add(SUMS, k, 1.0, Decimal("0.2"), window=WINDOW, maxlen=50)
    _check(first == (1, Decimal("0.1"), False), f"first add returned {first}")
    _check(second == (2, Decimal("0.3"), False), f"amounts must add exactly (got {second})")
    _check(
        s.snapshot(SUMS, k, 1.0, window=WINDOW) == (2, Decimal("0.3")),
        "snapshot must report entries and total",
    )
    _check(s.snapshot(SUMS, k, 1.0, window=WINDOW)[0] == 2, "snapshot must not record anything")
    aged = s.snapshot(SUMS, k, 10.5, window=WINDOW)
    _check(aged == (1, Decimal("0.2")), f"an expired amount must leave the total (got {aged})")
    _check(
        s.add(SUMS, k, 30.0, Decimal("5"), window=WINDOW, maxlen=50) == (1, Decimal("5"), False),
        "expired entries must not be counted by add",
    )

    small = make_store()
    outcomes = [
        small.add(SUMS, k, float(t), Decimal(t + 1), window=WINDOW, maxlen=2) for t in range(3)
    ]
    _check(
        outcomes == [(1, Decimal(1), False), (2, Decimal(3), False), (2, Decimal(5), True)],
        f"a full window must drop its oldest entry and report saturated=True (got {outcomes})",
    )


def _isolation(make_store: Callable[[], WindowStore]) -> None:
    s = make_store()
    s.hit(HITS, ("a", "b"), 0.0, window=WINDOW, maxlen=9)
    _check(s.count(HITS, ("ab",), 0.0, window=WINDOW) == 0, "key tuples must not be concatenated")
    _check(s.count(HITS, ("a",), 0.0, window=WINDOW) == 0, "a key must not match its prefix")
    _check(s.count("other.ns", ("a", "b"), 0.0, window=WINDOW) == 0, "namespaces must be isolated")
    s.add(SUMS, ("x",), 0.0, Decimal(1), window=WINDOW, maxlen=9)
    _check(s.snapshot(SUMS, ("y",), 0.0, window=WINDOW)[0] == 0, "sum keys must be isolated")
    _check(s.has_room(SUMS, [("x",)], 0.0, window=WINDOW), "an existing key always has room")
    _check(s.has_room(SUMS, [("never-seen",)], 0.0, window=WINDOW), "an unbounded store has room")


def _bounded(make_bounded: Callable[[int], WindowStore]) -> None:
    s = make_bounded(2)
    s.add(SUMS, ("a",), 0.0, Decimal(1), window=WINDOW, maxlen=9)
    s.add(SUMS, ("b",), 0.0, Decimal(1), window=WINDOW, maxlen=9)
    _check(not s.has_room(SUMS, [("c",)], 0.5, window=WINDOW), "a full store must report no room")
    try:
        s.add(SUMS, ("c",), 0.5, Decimal(1), window=WINDOW, maxlen=9)
    except WindowStoreFull:
        pass
    else:
        raise AssertionError("WindowStore contract: a new key in a full store must raise")
    _check(s.has_room(SUMS, [("a",)], 0.5, window=WINDOW), "an existing key still has room")
    _check(
        not s.has_room(SUMS, [("a",), ("c",)], 0.5, window=WINDOW),
        "room must be judged for the whole set of keys, not one at a time",
    )
    s.add(SUMS, ("a",), 0.5, Decimal(1), window=WINDOW, maxlen=9)  # must not raise
    # once the old keys have aged out of the window, room is reclaimed
    s.add(SUMS, ("c",), 100.0, Decimal(1), window=WINDOW, maxlen=9)
    _check(s.snapshot(SUMS, ("c",), 100.0, window=WINDOW)[0] == 1, "expired keys must be reclaimed")
