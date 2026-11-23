"""A second, deliberately naive WindowStore, written independently of the in-memory one.

It keeps every event in a plain list and recomputes on each call. If the detectors behave the same
on this store as on ``InMemoryWindowStore``, the protocol is sufficient for a host's own backend.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

from redhand_fintech_shield.protocols import WindowStoreFull


class ListWindowStore:
    def __init__(self, *, max_keys: Mapping[str, int] | None = None, **_ignored: Any) -> None:
        self._max = dict(max_keys or {})
        self._events: dict[tuple[str, tuple[str, ...]], list[tuple[float, Decimal]]] = {}

    def _live(
        self, namespace: str, key: tuple[str, ...], now: float, window: float
    ) -> list[tuple[float, Decimal]]:
        kept = [e for e in self._events.get((namespace, key), []) if e[0] > now - window]
        if kept:
            self._events[(namespace, key)] = kept
        else:
            self._events.pop((namespace, key), None)
        return kept

    def hit(
        self, namespace: str, key: tuple[str, ...], now: float, *, window: float, maxlen: int
    ) -> int:
        events = self._live(namespace, key, now, window)
        events.append((now, Decimal(0)))
        self._events[(namespace, key)] = events[-maxlen:]
        return len(self._events[(namespace, key)])

    def count(self, namespace: str, key: tuple[str, ...], now: float, *, window: float) -> int:
        return len(self._live(namespace, key, now, window))

    def has_room(
        self, namespace: str, keys: Sequence[tuple[str, ...]], now: float, *, window: float
    ) -> bool:
        limit = self._max.get(namespace)
        if limit is None:
            return True
        for other_ns, other_key in list(self._events):
            if other_ns == namespace:
                self._live(other_ns, other_key, now, window)  # drop keys whose events all expired
        stored = {k for ns, k in self._events if ns == namespace}
        return len(stored | set(keys)) <= limit

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
        if not self.has_room(namespace, [key], now, window=window):
            raise WindowStoreFull(namespace)
        events = self._live(namespace, key, now, window)
        saturated = len(events) >= maxlen
        if saturated:
            events = events[1:]
        events.append((now, amount))
        self._events[(namespace, key)] = events
        return len(events), sum((a for _, a in events), Decimal(0)), saturated

    def snapshot(
        self, namespace: str, key: tuple[str, ...], now: float, *, window: float
    ) -> tuple[int, Decimal]:
        events = self._live(namespace, key, now, window)
        return len(events), sum((a for _, a in events), Decimal(0))
