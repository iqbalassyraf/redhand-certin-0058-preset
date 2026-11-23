"""Sliding-window state for the detectors, behind a narrow ``WindowStore`` protocol.

Every stateful detector (micro-probe, velocity, sequence, structuring, cumulative cap) keeps its
counts and sums in a :class:`~redhand_fintech_shield.protocols.WindowStore`. The default is the
in-process :class:`InMemoryWindowStore` below; a host application that runs several workers can
supply a shared store instead (see ``redhand_fintech_shield.testing.window_store_contract``).

Limits to know about a shared store: the shield's lock makes check-then-record atomic only inside
one process, so across workers a cumulative cap can overshoot by up to the number of concurrent
workers; and window times are the shield's ``monotonic`` readings, so workers sharing a store must
be given a shared time base (for example ``time.time``).
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Hashable, Mapping, Sequence
from decimal import Decimal
from itertools import islice

from .protocols import WindowStore, WindowStoreFull

# Namespaces: one per detector, so a shared store keeps their windows apart.
NS_MICRO = "micro"
NS_VELOCITY_TOOL = "velocity.tool"
NS_VELOCITY_TOTAL = "velocity.total"
NS_SEQUENCE = "sequence"
NS_STRUCTURING = "structuring"
NS_CAP = "cap"


class SlidingWindowCounter:
    """Count of events in the trailing window; ``deque`` of monotonic stamps, bounded size."""

    __slots__ = ("_stamps", "_window")

    def __init__(self, window_seconds: float, maxlen: int) -> None:
        self._window = window_seconds
        self._stamps: deque[float] = deque(maxlen=maxlen)

    def hit(self, now: float) -> int:
        """Record an event at ``now`` and return how many events are in the window (capped)."""
        stamps = self._stamps
        cutoff = now - self._window
        while stamps and stamps[0] <= cutoff:
            stamps.popleft()
        stamps.append(now)
        return len(stamps)

    def count(self, now: float) -> int:
        """Return how many events are in the trailing window without recording a new event."""
        stamps = self._stamps
        cutoff = now - self._window
        while stamps and stamps[0] <= cutoff:
            stamps.popleft()
        return len(stamps)

    def newest(self) -> float | None:
        return self._stamps[-1] if self._stamps else None

    def __len__(self) -> int:
        return len(self._stamps)


class KeyedSlidingWindow:
    """One bounded :class:`SlidingWindowCounter` per key, with amortized idle-key eviction."""

    def __init__(
        self,
        window_seconds: float,
        maxlen: int,
        *,
        sweep_every: int = 256,
        sweep_batch: int = 256,
    ) -> None:
        self._window = window_seconds
        self._maxlen = maxlen
        self._counters: dict[Hashable, SlidingWindowCounter] = {}
        self._sweep_every = sweep_every
        self._sweep_batch = sweep_batch
        self._ops = 0

    def hit(self, key: Hashable, now: float) -> int:
        counter = self._counters.get(key)
        if counter is None:
            counter = self._counters[key] = SlidingWindowCounter(self._window, self._maxlen)
        count = counter.hit(now)
        self._ops += 1
        if self._ops % self._sweep_every == 0:
            self._sweep(now)
        return count

    def count(self, key: Hashable, now: float) -> int:
        """Return the active count for ``key`` at ``now`` without recording a new event."""
        counter = self._counters.get(key)
        if counter is None:
            return 0
        n = counter.count(now)
        if n == 0:
            del self._counters[key]
        return n

    def _sweep(self, now: float) -> None:
        """Bounded rotating sweep: examine a few keys, drop idle ones, rotate survivors."""
        cutoff = now - self._window
        for key in list(islice(self._counters, self._sweep_batch)):
            counter = self._counters[key]
            newest = counter.newest()
            if newest is None or newest <= cutoff:
                del self._counters[key]
            else:
                self._counters[key] = self._counters.pop(key)

    def __len__(self) -> int:
        return len(self._counters)


# --------------------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------------------


class _WindowSum:
    """Bounded O(1)-amortized sliding-window sum of Decimal amounts."""

    __slots__ = ("_entries", "_maxlen", "_total", "_window")

    def __init__(self, window_seconds: float, maxlen: int) -> None:
        self._window = window_seconds
        self._maxlen = maxlen
        self._entries: deque[tuple[float, Decimal]] = deque()
        self._total = Decimal("0")

    def _expire(self, now: float) -> None:
        entries = self._entries
        cutoff = now - self._window
        while entries and entries[0][0] <= cutoff:
            _, old = entries.popleft()
            self._total -= old

    def add(self, now: float, amount: Decimal) -> tuple[int, Decimal, bool]:
        self._expire(now)
        entries = self._entries
        saturated = len(entries) >= self._maxlen
        if saturated:
            _, dropped = entries.popleft()
            self._total -= dropped
        entries.append((now, amount))
        self._total += amount
        return len(entries), self._total, saturated

    def snapshot(self, now: float) -> tuple[int, Decimal]:
        """Entries and total in the window at ``now``, without recording anything."""
        self._expire(now)
        return len(self._entries), self._total

    def newest(self) -> float | None:
        return self._entries[-1][0] if self._entries else None


class _WindowTable:
    """Keyed :class:`_WindowSum` windows with amortised idle eviction and a hard key limit.

    The key space can be attacker controlled (a payee id), so it is bounded: at the limit, expired
    windows are purged (at most once a second, so a full table cannot be turned into a CPU sink)
    and if there is still no room the caller must fail closed.
    """

    def __init__(
        self,
        window_seconds: float,
        *,
        max_entries: int,
        max_keys: int,
        sweep_every: int,
        sweep_batch: int,
    ) -> None:
        self.window = window_seconds
        self.max_entries = max_entries
        self._max_keys = max_keys
        self._sweep_every = sweep_every
        self._sweep_batch = sweep_batch
        self._windows: dict[tuple[str, ...], _WindowSum] = {}
        self._ops = 0
        self._last_purge = -math.inf

    def get(self, key: tuple[str, ...]) -> _WindowSum | None:
        return self._windows.get(key)

    def has_room(self, now: float, new_keys: int = 1) -> bool:
        if len(self._windows) + new_keys <= self._max_keys:
            return True
        if now - self._last_purge >= 1.0:
            self._last_purge = now
            cutoff = now - self.window
            for key in [
                k for k, w in self._windows.items() if (n := w.newest()) is None or n <= cutoff
            ]:
                del self._windows[key]
        return len(self._windows) + new_keys <= self._max_keys

    def get_or_create(self, key: tuple[str, ...]) -> _WindowSum:
        win = self._windows.get(key)
        if win is None:
            win = self._windows[key] = _WindowSum(self.window, self.max_entries)
        return win

    def tick(self, now: float) -> None:
        self._ops += 1
        if self._ops % self._sweep_every == 0:
            cutoff = now - self.window
            for key in list(islice(self._windows, self._sweep_batch)):
                win = self._windows[key]
                newest = win.newest()
                if newest is None or newest <= cutoff:
                    del self._windows[key]
                else:
                    self._windows[key] = self._windows.pop(key)

    def __len__(self) -> int:
        return len(self._windows)


class InMemoryWindowStore:
    """The default :class:`WindowStore`: bounded, thread-compatible, one process.

    ``max_keys`` limits how many distinct windows a namespace may hold (counters are only swept,
    sums are limited); at the limit expired windows are purged at most once a second and a new key
    then raises :class:`WindowStoreFull`, which the detectors turn into a fail-closed violation.
    A namespace must always be used with the same ``window`` and ``maxlen``.
    """

    def __init__(
        self,
        *,
        max_keys: Mapping[str, int] | None = None,
        sweep_every: int = 256,
        sweep_batch: int = 256,
    ) -> None:
        self._max_keys = dict(max_keys or {})
        self._sweep_every = sweep_every
        self._sweep_batch = sweep_batch
        self._counters: dict[str, KeyedSlidingWindow] = {}
        self._tables: dict[str, _WindowTable] = {}

    def hit(
        self, namespace: str, key: tuple[str, ...], now: float, *, window: float, maxlen: int
    ) -> int:
        counters = self._counters.get(namespace)
        if counters is None:
            counters = self._counters[namespace] = KeyedSlidingWindow(
                window, maxlen, sweep_every=self._sweep_every, sweep_batch=self._sweep_batch
            )
        return counters.hit(key, now)

    def count(self, namespace: str, key: tuple[str, ...], now: float, *, window: float) -> int:
        counters = self._counters.get(namespace)
        return 0 if counters is None else counters.count(key, now)

    def _table(self, namespace: str, window: float, maxlen: int) -> _WindowTable:
        table = self._tables.get(namespace)
        if table is None:
            table = self._tables[namespace] = _WindowTable(
                window,
                max_entries=maxlen,
                max_keys=self._max_keys.get(namespace, 2**62),
                sweep_every=self._sweep_every,
                sweep_batch=self._sweep_batch,
            )
        return table

    def add(
        self,
        namespace: str,
        key: tuple[str, ...],
        now: float,
        amount: Decimal,
        *,
        window: float,
        maxlen: int,
    ) -> tuple[int, Decimal, bool]:
        table = self._table(namespace, window, maxlen)
        entry = table.get(key)
        if entry is None:
            if not table.has_room(now):
                raise WindowStoreFull(f"{namespace}: too many distinct keys")
            entry = table.get_or_create(key)
        result = entry.add(now, amount)
        table.tick(now)
        return result

    def snapshot(
        self, namespace: str, key: tuple[str, ...], now: float, *, window: float
    ) -> tuple[int, Decimal]:
        table = self._tables.get(namespace)
        entry = None if table is None else table.get(key)
        return (0, Decimal(0)) if entry is None else entry.snapshot(now)

    def has_room(
        self, namespace: str, keys: Sequence[tuple[str, ...]], now: float, *, window: float
    ) -> bool:
        table = self._tables.get(namespace)
        if table is None:  # nothing stored yet: the only question is whether the set fits at all
            limit = self._max_keys.get(namespace)
            return limit is None or len(set(keys)) <= limit
        new = {k for k in keys if table.get(k) is None}
        return not new or table.has_room(now, len(new))


def default_window_store(
    *,
    max_keys: Mapping[str, int] | None = None,
    sweep_every: int = 256,
    sweep_batch: int = 256,
) -> WindowStore:
    """The store a detector or shield builds when none is supplied."""
    return InMemoryWindowStore(max_keys=max_keys, sweep_every=sweep_every, sweep_batch=sweep_batch)
